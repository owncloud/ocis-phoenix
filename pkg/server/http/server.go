package http

import (
	mclient "github.com/micro/go-micro/v2/client"
	phoenixmid "github.com/owncloud/ocis-phoenix/pkg/middleware"
	svc "github.com/owncloud/ocis-phoenix/pkg/service/v0"
	"github.com/owncloud/ocis-phoenix/pkg/version"
	"github.com/owncloud/ocis-pkg/v2/account"
	"github.com/owncloud/ocis-pkg/v2/middleware"
	"github.com/owncloud/ocis-pkg/v2/roles"
	"github.com/owncloud/ocis-pkg/v2/service/http"
	settings "github.com/owncloud/ocis-settings/pkg/proto/v0"
	"time"
)

// Server initializes the http service and server.
func Server(opts ...Option) (http.Service, error) {
	options := newOptions(opts...)

	service := http.NewService(
		http.Logger(options.Logger),
		http.Namespace(options.Config.HTTP.Namespace),
		http.Name("phoenix"),
		http.Version(version.String),
		http.Address(options.Config.HTTP.Addr),
		http.Context(options.Context),
		http.Flags(options.Flags...),
	)

	// TODO this won't work with a registry other than mdns. Look into Micro's client initialization.
	// https://github.com/owncloud/ocis-proxy/issues/38
	rs := settings.NewRoleService("com.owncloud.api.settings", mclient.DefaultClient)
	roleCache := roles.NewCache(roles.Size(1024), roles.TTL(time.Hour*24*7))
	handle := svc.NewService(
		svc.Logger(options.Logger),
		svc.Config(options.Config),
		svc.RoleCache(&roleCache),
		svc.Middleware(
			middleware.RealIP,
			middleware.RequestID,
			middleware.Cache,
			middleware.Cors,
			middleware.Secure,
			phoenixmid.SilentRefresh,
			middleware.Version(
				"phoenix",
				version.String,
			),
			middleware.Logger(
				options.Logger,
			),
			middleware.ExtractAccountUUID(
				account.JWTSecret(options.Config.TokenManager.JWTSecret),
				account.Logger(options.Logger),
			),
			middleware.Roles(
				options.Logger,
				rs,
				&roleCache,
			),
		),
	)

	{
		handle = svc.NewInstrument(handle, options.Metrics)
		handle = svc.NewLogging(handle, options.Logger)
		handle = svc.NewTracing(handle)
	}

	service.Handle(
		"/",
		handle,
	)

	service.Init()
	return service, nil
}
