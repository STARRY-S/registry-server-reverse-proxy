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
	serverURL *url.URL
	addr      string // proxy server address
	port      int    // proxy server port
	protocol  string // http or https

	cert string
	key  string

	remoteURL             string
	insecureSkipTLSVerify bool
	hookLocation          bool

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

	server *http.Server
	mux    *http.ServeMux
	errCh  chan error
}

func NewRegistryServer(
	ctx context.Context, c *config.Config,
) (*registryServer, error) {
	s := &registryServer{
		serverURL:             nil,
		addr:                  c.BindAddr,
		port:                  c.Port,
		remoteURL:             c.RemoteURL,
		hookLocation:          c.HookLocation,
		insecureSkipTLSVerify: c.InsecureSkipTLSVerify,
		errCh:                 make(chan error),
		manifestProxyMap:      make(map[string]*httputil.ReverseProxy),
		blobsProxyMap:         make(map[string]*httputil.ReverseProxy),
		apiProxy:              nil,
		plaintextProxyMap:     make(map[string]config.PlainText),
		staticFileProxyMap:    make(map[string]string),
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL %s: %w", c.ServerURL, err)
	}
	s.serverURL = u
	if err := s.registerAPIFactory(ctx); err != nil {
		return nil, fmt.Errorf("failed to register API factory: %w", err)
	}
	for _, r := range c.Repositories {
		if err := s.registerRepository(ctx, &r); err != nil {
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

func (s *registryServer) registerRepository(
	ctx context.Context, r *config.Repository,
) error {
	// https://127.0.0.1:5000/v2/library/NAME/manifests/latest
	manifestRawURLPrefix, err := url.JoinPath(s.remoteURL, "v2", r.Name)
	if err != nil {
		return fmt.Errorf("failed to join manifest URL for repository %s: %w", r.Name, err)
	}

	// https://127.0.0.1:5000/v2/library/NAME/blobs/sha256:aabbccdd....
	blobsRawURLPrefix, err := url.JoinPath(s.remoteURL, "v2", r.Name, "blobs")
	if err != nil {
		return fmt.Errorf("failed to join blobs URL for repository %s: %w", r.Name, err)
	}

	manifestFactory, err := NewManifestFactory(
		ctx, manifestRawURLPrefix, s.insecureSkipTLSVerify)
	if err != nil {
		return fmt.Errorf("failed to create manifest factory for repository %s: %w", r.Name, err)
	}
	s.manifestProxyMap[r.Name] = manifestFactory.Proxy()

	blobsFactory, err := NewBlobsFactory(
		ctx, blobsRawURLPrefix, s.insecureSkipTLSVerify)
	if err != nil {
		return fmt.Errorf("failed to create blobs factory for repository %s: %w", r.Name, err)
	}
	s.blobsProxyMap[r.Name] = blobsFactory.Proxy()
	logrus.Debugf("Registered repository [%s] with manifest URL [%s]",
		r.Name, manifestRawURLPrefix)
	logrus.Debugf("Registered repository [%s] with blobs URL [%s]",
		r.Name, manifestRawURLPrefix)

	return nil
}

func (s *registryServer) registerAPIFactory(ctx context.Context) error {
	apiFactory, err := NewAPIFactory(
		ctx, s.remoteURL, s.serverURL, s.insecureSkipTLSVerify)
	if err != nil {
		return fmt.Errorf("failed to create api factory: %w", err)
	}
	s.apiProxy = apiFactory.Proxy()
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.ServeHTTP)
	addr := fmt.Sprintf("%v:%v", s.addr, s.port)
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: time.Second * 10,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: s.insecureSkipTLSVerify,
		},
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return fmt.Errorf("failed to configure http2 server: %v", err)
	}
	s.server = server
	s.mux = mux
	logrus.Infof("server listen on %v://%v", s.protocol, addr)
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

func (s *registryServer) Listen(ctx context.Context) error {
	s.protocol = "http"
	if err := s.initServer(); err != nil {
		return err
	}
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.errCh <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	return s.waitServerShutDown(ctx)
}

func (s *registryServer) ListenTLS(ctx context.Context) error {
	s.protocol = "https"
	if err := s.initServer(); err != nil {
		return err
	}
	go func() {
		if err := s.server.ListenAndServeTLS(s.cert, s.key); err != nil {
			logrus.Warnf("error: %v", err)
			s.errCh <- fmt.Errorf("failed to start http2 server: %w", err)
		}
	}()
	return s.waitServerShutDown(ctx)
}
