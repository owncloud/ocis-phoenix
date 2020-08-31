package svc

import (
	"github.com/owncloud/ocis-pkg/v2/roles"
	"net/http"

	"github.com/owncloud/ocis-phoenix/pkg/config"
	"github.com/owncloud/ocis-pkg/v2/log"
)

// Option defines a single option function.
type Option func(o *Options)

// Options defines the available options for this package.
type Options struct {
	Logger     log.Logger
	Config     *config.Config
	Middleware []func(http.Handler) http.Handler
	RoleCache  *roles.Cache
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

// RoleCache provides a function to set the roles cache option.
func RoleCache(val *roles.Cache) Option {
	return func(o *Options) {
		o.RoleCache = val
	}
}
