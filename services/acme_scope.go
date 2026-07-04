package services

import "context"

type acmeJobScope struct {
	isActive func() bool
}

type acmeJobScopeKey struct{}

// WithCertJobScope attaches a liveness check for in-flight ACME work. DNS and ACME
// helpers treat a false result like cancellation so superseded jobs stop touching DNS.
func WithCertJobScope(ctx context.Context, isActive func() bool) context.Context {
	if isActive == nil {
		return ctx
	}
	return context.WithValue(ctx, acmeJobScopeKey{}, acmeJobScope{isActive: isActive})
}

func requireACMEActive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, ok := ctx.Value(acmeJobScopeKey{}).(acmeJobScope)
	if !ok || scope.isActive == nil {
		return nil
	}
	if !scope.isActive() {
		return context.Canceled
	}
	return nil
}
