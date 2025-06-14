package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

type apiFactory struct {
	remoteURL             *url.URL
	localURL              *url.URL
	insecureSkipTLSVerify bool

	director       func(r *http.Request)
	modifyResponse func(r *http.Response) error
	errorHandler   func(w http.ResponseWriter, r *http.Request, err error)
}

func (f *apiFactory) defaultDirector(r *http.Request) {
	// Change host
	r.Host = f.remoteURL.Host
	r.URL.Scheme = f.remoteURL.Scheme
	r.URL.Host = f.remoteURL.Host

	// Dump request debug data
	if logrus.GetLevel() >= logrus.DebugLevel {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			logrus.Debugf("failed to dump request: %v", err)
		} else {
			logrus.Debugf("API FACTORY MODIFIED REQUEST %q\n%v", r.URL.Path, string(b))
		}
	}
}

func (f *apiFactory) defaultModifyResponse(r *http.Response) error {
	// Re-write the Location/Auth header if exists
	// https://registry.example.com/service/token
	auth := r.Header.Get("Www-Authenticate")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer realm=") {
			logrus.Debugf("replace response header [%v] the [%v] with [%v]",
				auth, f.remoteURL.String(), f.localURL.String())
			auth = strings.ReplaceAll(auth, f.remoteURL.String(), f.localURL.String())
			r.Header.Set("Www-Authenticate", auth)
		}
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		// Dump response debug data
		b, err := httputil.DumpResponse(r, false)
		if err != nil {
			logrus.Debugf("failed to dump response: %v", err)
		} else {
			logrus.Debugf("API FACTORY MODIFIED RESPONSE %q\n%v",
				r.Request.URL.Path, string(b))
		}
	}
	return nil
}

func (f *apiFactory) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logrus.Errorf("Error on API handler [%v]: %v", r.URL.Path, err)
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(fmt.Sprintf("%v", err)))
}

// Factory is the generator factory for SingleReverseProxy Server
func NewAPIFactory(
	ctx context.Context, remoteRawURL string, serverURL *url.URL, insecure bool,
) (*apiFactory, error) {
	u, err := url.Parse(remoteRawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}
	f := &apiFactory{
		remoteURL:             u,
		localURL:              serverURL,
		insecureSkipTLSVerify: insecure,
	}
	f.errorHandler = f.defaultErrorHandler
	// Register new modifyResponse function for hook location
	f.modifyResponse = f.defaultModifyResponse
	f.director = f.defaultDirector
	return f, nil
}

// Set Directory hook to proxy server
func (f *apiFactory) RegisterDirector(cb func(r *http.Request)) {
	f.director = func(r *http.Request) {
		// Change host
		r.Host = f.remoteURL.Host
		r.URL.Scheme = f.remoteURL.Scheme
		r.URL.Host = f.remoteURL.Host
		cb(r)
	}
}

// Set ModifyResponse hook to proxy server
func (f *apiFactory) RegisterModifyResponse(cb func(r *http.Response) error) {
	f.modifyResponse = cb
}

// Set ErrorHandler hook to proxy server
func (f *apiFactory) RegisterErrorHandler(cb func(w http.ResponseWriter, r *http.Request, err error)) {
	f.errorHandler = cb
}

// Proxy generates the ReverseProxy server
func (f *apiFactory) Proxy() *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(f.remoteURL)
	p.Director = f.director
	p.ModifyResponse = f.modifyResponse
	p.ErrorHandler = f.errorHandler
	return p
}
