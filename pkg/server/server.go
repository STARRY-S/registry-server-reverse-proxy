package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/config"
	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

type registryServer struct {
	serverURL *url.URL // proxy server actual http url (localURL)
	addr      string   // proxy server bind address
	port      int      // proxy server bind port

	cert string
	key  string

	remoteURL             *url.URL // the proxied remote registry URL
	insecureSkipTLSVerify bool

	// Manifest index proxy map, the manifest index should not be cached by CDN
	manifestProxyMap map[string]*httputil.ReverseProxy // map[repository]Proxy
	// Blobs proxy map, the blobs can be cached by CDN in a long period if the image is public
	blobsProxyMap map[string]*httputil.ReverseProxy // map[repository]Proxy
	// API proxy, proxy other registry v2 API requests, should not be cached by CDN
	apiProxy *httputil.ReverseProxy

	// Custom plaintext proxy map, can be cached by CDN in a short period
	plaintextProxyMap map[string]config.PlainText // map[prefix]PlainText
	// Custom static file proxy map, can be cached by CDN in a short period
	staticFileProxyMap map[string]string // map[prefix]FilePath

	server *http.Server   // HTTP2 server
	mux    *http.ServeMux // HTTP request multiplexer
	errCh  chan error
}

func NewRegistryServer(
	ctx context.Context, c *config.Config,
) (*registryServer, error) {
	var err error
	s := &registryServer{
		serverURL:             nil,
		addr:                  c.BindAddr,
		port:                  c.Port,
		remoteURL:             nil,
		insecureSkipTLSVerify: c.InsecureSkipTLSVerify,
		errCh:                 make(chan error),
		manifestProxyMap:      make(map[string]*httputil.ReverseProxy),
		blobsProxyMap:         make(map[string]*httputil.ReverseProxy),
		apiProxy:              nil,
		plaintextProxyMap:     make(map[string]config.PlainText),
		staticFileProxyMap:    make(map[string]string),
	}
	s.serverURL, err = url.Parse(c.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL %s: %w", c.ServerURL, err)
	}
	s.remoteURL, err = url.Parse(c.RemoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote URL %s: %w", c.RemoteURL, err)
	}
	if err := s.registerAPIFactory(); err != nil {
		return nil, fmt.Errorf("failed to register API factory: %w", err)
	}
	for _, r := range c.Repositories {
		if err := s.registerRepository(&r); err != nil {
			return nil, fmt.Errorf("failed to register repository %s: %w", r.Name, err)
		}
	}

	for _, r := range c.CustomRoutes {
		if r.Prefix == "" {
			logrus.Warnf("ignore route %q: prefix not set", r.Name)
			continue
		}

		if r.PlainText != nil {
			s.registerPlainText(r.Prefix, r.PlainText)
			continue
		}
		if r.StaticFile != "" {
			s.registerStaticFile(r.Prefix, r.StaticFile)
			continue
		}
	}

	return s, nil
}

func (s *registryServer) registerPlainText(prefix string, c *config.PlainText) {
	s.plaintextProxyMap[prefix] = *c
}

func (s *registryServer) registerStaticFile(prefix string, f string) {
	s.staticFileProxyMap[prefix] = f
}

func (s *registryServer) registerManifestFactory(r *config.Repository) error {
	// https://registry_url/v2/REPO_NAME/manifests/latest
	manifestPrefixURL := s.remoteURL.JoinPath("v2", r.Name)
	f := &factory{
		kind:                  ManifestFactory,
		localURL:              s.serverURL,
		remoteURL:             s.remoteURL,
		prefixURL:             manifestPrefixURL,
		insecureSkipTLSVerify: s.insecureSkipTLSVerify,
	}
	f.errorHandler = f.defaultErrorHandler
	f.modifyResponse = f.defaultModifyResponse
	f.director = f.defaultDirector
	s.manifestProxyMap[r.Name] = f.Proxy()

	logrus.Debugf("Registered repository [%s] with manifest URL [%s]",
		r.Name, manifestPrefixURL)

	return nil
}

func (s *registryServer) registerBlobsFactory(r *config.Repository) error {
	// https://registry_url/v2/REPO_NAME/blobs/sha256:aabbccdd....
	blobsPrefixURL := s.remoteURL.JoinPath("v2", r.Name, "blobs")
	f := &factory{
		kind:                  BlobsFactory,
		localURL:              s.serverURL,
		remoteURL:             s.remoteURL,
		prefixURL:             blobsPrefixURL,
		privateRepo:           r.Private,
		insecureSkipTLSVerify: s.insecureSkipTLSVerify,
	}
	f.errorHandler = f.defaultErrorHandler
	f.modifyResponse = f.defaultModifyResponse
	f.director = f.defaultDirector
	s.blobsProxyMap[r.Name] = f.Proxy()

	logrus.Debugf("Registered repository [%s] with blobs URL [%s]",
		r.Name, blobsPrefixURL)

	return nil
}

func (s *registryServer) registerAPIFactory() error {
	// https://registry_url/
	f := &factory{
		kind:                  APIFactory,
		localURL:              s.serverURL,
		remoteURL:             s.remoteURL,
		prefixURL:             s.remoteURL,
		privateRepo:           true, // Set to true for other API requests
		insecureSkipTLSVerify: s.insecureSkipTLSVerify,
	}
	f.errorHandler = f.defaultErrorHandler
	f.modifyResponse = f.defaultModifyResponse
	f.director = f.defaultDirector
	s.apiProxy = f.Proxy()

	logrus.Debugf("Registered default API request proxy")

	return nil
}

func (s *registryServer) registerRepository(r *config.Repository) error {
	if err := s.registerManifestFactory(r); err != nil {
		return fmt.Errorf("register manifest factory on repo [%v]: %w", r.Name, err)
	}
	if err := s.registerBlobsFactory(r); err != nil {
		return fmt.Errorf("register blobs factory on repo [%v]: %w", r.Name, err)
	}
	return nil
}

func (s *registryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	logrus.Debugf("Proxy path [%v]", path)
	switch utils.DetectURLType(path) {
	case "manifest":
		for repo, fn := range s.manifestProxyMap {
			if !strings.HasPrefix(path, fmt.Sprintf("/v2/%s/", repo)) {
				continue
			}
			fn.ServeHTTP(w, r)
			return
		}
	case "blobs":
		for repo, fn := range s.blobsProxyMap {
			if !strings.HasPrefix(path, fmt.Sprintf("/v2/%s/", repo)) {
				continue
			}
			fn.ServeHTTP(w, r)
			return
		}
	default:
		for prefix, plainText := range s.plaintextProxyMap {
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			if plainText.Status != 0 {
				w.WriteHeader(plainText.Status)
			}
			w.Write([]byte(plainText.Content))
			logrus.Debugf("response plaintext prefix [%v] status [%v] content [%v]",
				prefix, plainText.Status, strings.TrimSpace(plainText.Content))
			return
		}

		for prefix, fileName := range s.staticFileProxyMap {
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			b, err := os.ReadFile(fileName)
			if err != nil {
				logrus.Warnf("failed to read file %q: %v", fileName, err)
			}
			w.Write(b)
			logrus.Debugf("response file [%v] prefix [%v]",
				fileName, prefix)
			return
		}
	}
	s.apiProxy.ServeHTTP(w, r)
}

func (s *registryServer) initServer() error {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", s.ServeHTTP)
	addr := fmt.Sprintf("%v:%v", s.addr, s.port)
	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: time.Second * 10,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: s.insecureSkipTLSVerify,
		},
	}
	if err := http2.ConfigureServer(s.server, &http2.Server{}); err != nil {
		return fmt.Errorf("failed to configure http2 server: %v", err)
	}
	logrus.Infof("server listen on %v://%v", s.serverURL.Scheme, addr)
	return nil
}

func (s *registryServer) waitServerShutDown(ctx context.Context) error {
	select {
	case err := <-s.errCh:
		return err
	case <-ctx.Done():
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		s.server.Shutdown(timeoutCtx)
		cancel()
		logrus.Warnf("%v", ctx.Err())
	}
	return nil
}

func (s *registryServer) Serve(ctx context.Context) error {
	if err := s.initServer(); err != nil {
		return err
	}
	go func() {
		var err error
		switch s.serverURL.Scheme {
		case "http":
			err = s.server.ListenAndServe()
		case "https":
			err = s.server.ListenAndServeTLS(s.cert, s.key)
		default:
			err = fmt.Errorf("unsupported url scheme %q", s.serverURL.Scheme)
		}

		if err != nil {
			s.errCh <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	return s.waitServerShutDown(ctx)
}
