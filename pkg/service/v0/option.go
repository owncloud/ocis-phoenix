package svc

import (
	"net/http"

	"github.com/micro/go-micro/registry"
	"github.com/owncloud/ocis-phoenix/pkg/config"
	"github.com/owncloud/ocis-pkg/log"
)

// Option defines a single option function.
type Option func(o *Options)

// Options defines the available options for this package.
type Options struct {
	Logger     log.Logger
	Config     *config.Config
	Middleware []func(http.Handler) http.Handler
	Registry   registry.Registry
}

// newOptions initializes the available default options.
func newOptions(opts ...Option) Options {
	opt := Options{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// Logger provides a function to set the logger option.
func Logger(val log.Logger) Option {
	return func(o *Options) {
		o.Logger = val
	}
}

// Config provides a function to set the config option.
func Config(val *config.Config) Option {
	return func(o *Options) {
		o.Config = val
	}
}

// Middleware provides a function to set the middleware option.
func Middleware(val ...func(http.Handler) http.Handler) Option {
	return func(o *Options) {
		o.Middleware = val
	}
}

// Registry provides a function to set the registry option.
func Registry(val registry.Registry) Option {
	return func(o *Options) {
		o.Registry = val
	}
}
