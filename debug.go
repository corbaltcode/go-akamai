package akamai

import "context"

// AkamaiContext is a context value type used to enable various features of the go-akamai library.
type AkamaiContext int

// AkamaiDebug is a context value that can be set to enable debug logging in the go-akamai library.
const AkamaiDebug AkamaiContext = 0

// WithDebugEnabled returns a copy of the parent context with debug enabled.
func WithDebugEnabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, AkamaiDebug, true)
}

// DebugEnabled returns true if the context has debug enabled.
func DebugEnabled(ctx context.Context) bool {
	debugAny := ctx.Value(AkamaiDebug)
	debug, _ := debugAny.(bool)
	return debug
}
