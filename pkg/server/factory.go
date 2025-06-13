package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/config"
	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/utils"
	"github.com/sirupsen/logrus"
)

type factory struct {
	prefix                string
	targetURL             *url.URL
	insecureSkipTLSVerify bool

	director       func(r *http.Request)
	modifyResponse func(r *http.Response) error
	errorHandler   func(w http.ResponseWriter, r *http.Request, err error)
}

func (f *factory) defaultDirector(r *http.Request) {
	// Change host
	r.Host = f.targetURL.Host
	r.URL.Scheme = f.targetURL.Scheme
	r.URL.Host = f.targetURL.Host

	// Dump request debug data
	b, err := httputil.DumpRequest(r, true)
	if err != nil {
		logrus.Debugf("failed to dump request: %v", err)
	} else {
		logrus.Debugf("MODIFIED REQUEST %q\n%v", f.prefix, string(b))
	}
}

func (f *factory) defaultModifyResponse(r *http.Response) error {
	if logrus.GetLevel() >= logrus.DebugLevel {
		// Dump response debug data
		b, err := httputil.DumpResponse(r, false)
		if err != nil {
			logrus.Debugf("failed to dump response: %v", err)
		} else {
			logrus.Debugf("MODIFIED RESPONSE %q\n%v", f.prefix, string(b))
		}
	}
	return nil
}

func (f *factory) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logrus.Errorf("error on factory %v: %v", f.prefix, err)
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(fmt.Sprintf("%v", err)))
}

// Factory is the generator factory for SingleReverseProxy Server
func NewRemoteFactory(
	ctx context.Context, r *config.Route, insecure bool,
) (*factory, error) {
	u, err := url.Parse(r.Remote.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}
	f := &factory{
		prefix:                r.Prefix,
		targetURL:             u,
		insecureSkipTLSVerify: insecure,
	}
	f.errorHandler = f.defaultErrorHandler
	if r.Remote.HookLocation {
		// Register new modifyResponse function
		f.modifyResponse = func(r *http.Response) error {
			defer f.defaultModifyResponse(r)

			location := r.Header.Get("Location")
			if location == "" {
				return nil
			}
			res, err := utils.HttpGet(ctx, location, insecure)
			if err != nil {
				logrus.Errorf("%v", err)
				return err
			}
			if err := r.Body.Close(); err != nil {
				logrus.Errorf("failed to close response: %v", err)
			}
			r.Body = res.Body
			r.Header = res.Header
			r.ContentLength = res.ContentLength
			r.Status = res.Status
			r.StatusCode = res.StatusCode
			r.Proto = res.Proto
			r.Close = res.Close
			r.ProtoMajor = res.ProtoMajor
			r.ProtoMinor = res.ProtoMinor
			return nil
		}
	}
	f.director = f.defaultDirector
	return f, nil
}

// Set Directory hook to proxy server
func (f *factory) RegisterDirector(cb func(r *http.Request)) {
	f.director = func(r *http.Request) {
		// Change host
		r.Host = f.targetURL.Host
		r.URL.Scheme = f.targetURL.Scheme
		r.URL.Host = f.targetURL.Host
		cb(r)
	}
}

// Set ModifyResponse hook to proxy server
func (f *factory) RegisterModifyResponse(cb func(r *http.Response) error) {
	f.modifyResponse = cb
}

// Set ErrorHandler hook to proxy server
func (f *factory) RegisterErrorHandler(cb func(w http.ResponseWriter, r *http.Request, err error)) {
	f.errorHandler = cb
}

// Proxy generates the ReverseProxy server
func (f *factory) Proxy() *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(f.targetURL)
	p.Director = f.director
	p.ModifyResponse = f.modifyResponse
	p.ErrorHandler = f.errorHandler
	return p
}
