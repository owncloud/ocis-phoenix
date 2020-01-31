package svc

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/micro/go-micro"
	"github.com/owncloud/ocis-phoenix/pkg/assets"
	"github.com/owncloud/ocis-phoenix/pkg/config"
	"github.com/owncloud/ocis-pkg/log"
	"github.com/owncloud/ocis-pkg/oidc"
	accounts "github.com/owncloud/ocis-accounts/pkg/proto/v0"
)

var (
	// ErrConfigInvalid is returned when the config parse is invalid.
	ErrConfigInvalid = `Invalid or missing config`
)

// Service defines the extension handlers.
type Service interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	Config(http.ResponseWriter, *http.Request)
}

// NewService returns a service implementation for Service.
func NewService(opts ...Option) Service {
	options := newOptions(opts...)

	m := chi.NewMux()
	m.Use(options.Middleware...)

	svc := Phoenix{
		logger: options.Logger,
		config: options.Config,
		mux:    m,
	}

	m.Route(options.Config.HTTP.Root, func(r chi.Router) {
		r.Get("/config.json", svc.Config)
		r.Mount("/", svc.Static())
	})

	return svc
}

// Phoenix defines implements the business logic for Service.
type Phoenix struct {
	logger log.Logger
	config *config.Config
	mux    *chi.Mux
}

// ServeHTTP implements the Service interface.
func (p Phoenix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p Phoenix) getPayload(ctx context.Context) (payload []byte, err error) {

	if p.config.Phoenix.Path == "" {
		// render dynamically using config

		// make apps render as empty array if it is empty
		// TODO remove once https://github.com/golang/go/issues/27589 is fixed
		if len(p.config.Phoenix.Config.Apps) == 0 {
			p.config.Phoenix.Config.Apps = make([]string, 0)
		}


		// we will never get claims here because the config is not auth protected, the bearer token is never parsed and the context never filled with the claims
		claims := oidc.FromContext(ctx)

		if claims != nil {
			key := claims.Sub

			// override theme if accounts services has a value
			service := micro.NewService()
			service.Init()

			c := service.Client()

			req := c.NewRequest("com.owncloud.accounts", "SettingsService.Get", &accounts.Query{
				Key: key,
			})
			
			rsp := &accounts.Record{}

			if err := c.Call(ctx, req, rsp); err == nil {
				if rsp.Payload.Phoenix.Theme != "" {
					p.config.Phoenix.Config.Theme = rsp.Payload.Phoenix.Theme
				}
			} 
			// TODO log error?
		}
		// TODO not logged in

		return json.Marshal(p.config.Phoenix.Config)
	}

	// try loading from file
	if _, err = os.Stat(p.config.Phoenix.Path); os.IsNotExist(err) {
		p.logger.Error().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("Phoenix config doesn't exist")
		return
	}

	payload, err = ioutil.ReadFile(p.config.Phoenix.Path)

	if err != nil {
		p.logger.Error().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("Failed to read custom config")

	}
	return
}

// Config implements the Service interface.
func (p Phoenix) Config(w http.ResponseWriter, r *http.Request) {

	payload, err := p.getPayload(r.Context())
	if err != nil {
		http.Error(w, ErrConfigInvalid, http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

// Static simply serves all static files.
func (p Phoenix) Static() http.HandlerFunc {
	rootWithSlash := p.config.HTTP.Root

	if !strings.HasSuffix(rootWithSlash, "/") {
		rootWithSlash = rootWithSlash + "/"
	}

	static := http.StripPrefix(
		rootWithSlash,
		http.FileServer(
			assets.New(
				assets.Logger(p.logger),
				assets.Config(p.config),
			),
		),
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rootWithSlash != "/" && r.URL.Path == p.config.HTTP.Root {
			http.Redirect(
				w,
				r,
				rootWithSlash,
				http.StatusMovedPermanently,
			)

			return
		}

		if r.URL.Path != rootWithSlash && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(
				w,
				r,
			)

			return
		}

		static.ServeHTTP(w, r)
	})
}
