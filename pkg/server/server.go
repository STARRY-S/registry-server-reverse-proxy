package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

type proxyServer struct {
	addr                  string
	port                  int
	protocol              string
	insecureSkipTLSVerify bool

	cert string
	key  string

	remoteProxyMap     map[string]*httputil.ReverseProxy // map[prefix]Proxy
	plaintextProxyMap  map[string]config.PlainText       // map[prefix]PlainText
	staticFileProxyMap map[string]string                 // map[prefix]FilePath

	server *http.Server
	mux    *http.ServeMux
	errCh  chan error
}

type Options struct {
	Addr                  string
	Port                  int
	InsecureSkipTLSVerify bool
	Cert                  string
	Key                   string
}

func NewProxyServer(o *Options) *proxyServer {
	return &proxyServer{
		addr:                  o.Addr,
		port:                  o.Port,
		insecureSkipTLSVerify: o.InsecureSkipTLSVerify,
		cert:                  o.Cert,
		key:                   o.Key,
		errCh:                 make(chan error),
		remoteProxyMap:        make(map[string]*httputil.ReverseProxy),
		plaintextProxyMap:     make(map[string]config.PlainText),
		staticFileProxyMap:    make(map[string]string),
	}
}

func (p *proxyServer) RegisterRemote(f *factory) {
	p.remoteProxyMap[f.prefix] = f.Proxy()
}

func (p *proxyServer) RegisterPlainText(prefix string, c *config.PlainText) {
	p.plaintextProxyMap[prefix] = *c
}

func (p *proxyServer) RegisterStaticFile(prefix string, f string) {
	p.staticFileProxyMap[prefix] = f
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	for prefix, fn := range p.remoteProxyMap {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		fn.ServeHTTP(w, r)
		return
	}

	for prefix, plainText := range p.plaintextProxyMap {
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

	for prefix, fileName := range p.staticFileProxyMap {
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

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 NOT FOUND"))
	logrus.Debugf("default status [404] content [NOT FOUND]")
}

func (p *proxyServer) initServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.ServeHTTP)
	addr := fmt.Sprintf("%v:%v", p.addr, p.port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: p.insecureSkipTLSVerify,
		},
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return fmt.Errorf("failed to configure http2.0 server: %v", err)
	}
	p.server = server
	p.mux = mux
	logrus.Infof("server listen on %v://%v", p.protocol, addr)
	return nil
}

func (p *proxyServer) waitServerShutDown(ctx context.Context) error {
	select {
	case err := <-p.errCh:
		return err
	case <-ctx.Done():
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		p.server.Shutdown(timeoutCtx)
		cancel()
		logrus.Warnf("%v", ctx.Err())
	}
	return nil
}

func (p *proxyServer) Listen(ctx context.Context) error {
	p.protocol = "http"
	if err := p.initServer(); err != nil {
		return err
	}
	go func() {
		if err := p.server.ListenAndServe(); err != nil {
			p.errCh <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	return p.waitServerShutDown(ctx)
}

func (p *proxyServer) ListenTLS(ctx context.Context) error {
	p.protocol = "https"
	if err := p.initServer(); err != nil {
		return err
	}
	go func() {
		if err := p.server.ListenAndServeTLS(p.cert, p.key); err != nil {
			logrus.Warnf("error: %v", err)
			p.errCh <- fmt.Errorf("failed to start http2 server: %w", err)
		}
	}()
	return p.waitServerShutDown(ctx)
}
