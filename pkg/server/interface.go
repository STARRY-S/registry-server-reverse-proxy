package server

import "context"

type Server interface {
	Listen(ctx context.Context) error
	ListenTLS(ctx context.Context) error
}
