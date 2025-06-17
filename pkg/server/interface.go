package server

import "context"

type Server interface {
	Serve(ctx context.Context) error
}

var _ Server = &registryServer{}
