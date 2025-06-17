package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/utils"
	"github.com/sirupsen/logrus"
)

type manifestFactory struct {
	remoteURL             *url.URL
	insecureSkipTLSVerify bool

	director       func(r *http.Request)
	modifyResponse func(r *http.Response) error
	errorHandler   func(w http.ResponseWriter, r *http.Request, err error)
}

func (f *manifestFactory) defaultDirector(r *http.Request) {
	// Change host
	r.Host = f.remoteURL.Host
	r.URL.Scheme = f.remoteURL.Scheme
	r.URL.Host = f.remoteURL.Host
	if r.Method == "PUT" {
		logrus.Infof("XXXX PUT")
	}

	// Dump request debug data
	if logrus.GetLevel() >= logrus.DebugLevel {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			logrus.Debugf("failed to dump request: %v", err)
		} else {
			logrus.Debugf("Manifest Factory MODIFIED REQUEST %q\n%v",
				r.URL.Path, string(b))
		}
	}
}

func (f *manifestFactory) defaultModifyResponse(r *http.Response) error {
	// Re-write the Location/Auth header if exists
	// https://registry.example.com/service/token
	auth := r.Header.Get("Www-Authenticate")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer realm=") {
			logrus.Debugf("replace manifest response header [%v] the [%v] with [%v]",
				auth, "https://harbor.hxstarrys.me", "http://127.0.0.1:8080")
			auth = strings.ReplaceAll(auth, "https://harbor.hxstarrys.me", "http://127.0.0.1:8080") // TODO:
			r.Header.Set("Www-Authenticate", auth)
		}
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		// Dump response debug data
		b, err := httputil.DumpResponse(r, false)
		if err != nil {
			logrus.Debugf("failed to dump response: %v", err)
		} else {
			logrus.Debugf("Manifest Factory MODIFIED RESPONSE %q\n%v",
				r.Request.URL.Path, string(b))
		}
	}
	return nil
}

func (f *manifestFactory) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logrus.Errorf("Error on manifest handler [%v]: %v", r.URL.Path, err)
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(fmt.Sprintf("%v", err)))
}

// Factory is the generator factory for SingleReverseProxy Server
func NewManifestFactory(
	ctx context.Context, rawURL string, insecure bool,
) (*manifestFactory, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}
	f := &manifestFactory{
		remoteURL:             u,
		insecureSkipTLSVerify: insecure,
	}
	f.errorHandler = f.defaultErrorHandler
	// Register new modifyResponse function for hook location
	f.modifyResponse = func(r *http.Response) error {
		defer f.defaultModifyResponse(r)

		// TODO: Need better logic
		location := r.Header.Get("Location")
		if location == "" {
			return nil
		}
		if r.Request.Method != "GET" && r.Request.Method != "HEAD" {
			// For non GET/HEAD method, update the location URL directly
			logrus.Debugf("replace manifest response header [%v] the [%v] with [%v]",
				location, "https://harbor.hxstarrys.me", "http://127.0.0.1:8080")
			location = strings.ReplaceAll(location, "https://harbor.hxstarrys.me", "http://127.0.0.1:8080") // TODO:
			r.Header.Set("Location", location)
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, r.Request.Method, location, nil)
		if err != nil {
			return fmt.Errorf("failed to create new request %q: %w", location, err)
		}

		req.Header = r.Request.Header
		res, err := utils.HTTPGet(ctx, req, insecure)
		if err != nil {
			logrus.Errorf("%v", err)
			return err
		}
		if err := r.Body.Close(); err != nil {
			logrus.Errorf("failed to close response: %v", err)
		}
		r.Body = res.Body
		r.Header = res.Header
		// Add no-cache headers for manifest response
		r.Header.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, proxy-revalidate")
		r.ContentLength = res.ContentLength
		r.Status = res.Status
		r.StatusCode = res.StatusCode
		r.Proto = res.Proto
		r.Close = res.Close
		r.ProtoMajor = res.ProtoMajor
		r.ProtoMinor = res.ProtoMinor
		return nil
	}
	f.director = f.defaultDirector
	return f, nil
}

// Set Directory hook to proxy server
func (f *manifestFactory) RegisterDirector(cb func(r *http.Request)) {
	f.director = func(r *http.Request) {
		// Change host
		r.Host = f.remoteURL.Host
		r.URL.Scheme = f.remoteURL.Scheme
		r.URL.Host = f.remoteURL.Host
		cb(r)
	}
}

// Set ModifyResponse hook to proxy server
func (f *manifestFactory) RegisterModifyResponse(cb func(r *http.Response) error) {
	f.modifyResponse = cb
}

// Set ErrorHandler hook to proxy server
func (f *manifestFactory) RegisterErrorHandler(cb func(w http.ResponseWriter, r *http.Request, err error)) {
	f.errorHandler = cb
}

// Proxy generates the ReverseProxy server
func (f *manifestFactory) Proxy() *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(f.remoteURL)
	p.Director = f.director
	p.ModifyResponse = f.modifyResponse
	p.ErrorHandler = f.errorHandler
	return p
}
