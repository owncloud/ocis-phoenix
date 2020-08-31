package svc

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/jinzhu/copier"
	asvc "github.com/owncloud/ocis-accounts/pkg/service/v0"
	"github.com/owncloud/ocis-phoenix/pkg/assets"
	"github.com/owncloud/ocis-phoenix/pkg/config"
	"github.com/owncloud/ocis-pkg/v2/log"
	"github.com/owncloud/ocis-pkg/v2/middleware"
	"github.com/owncloud/ocis-pkg/v2/roles"
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
		logger:    options.Logger,
		config:    options.Config,
		mux:       m,
		roleCache: options.RoleCache,
	}

	m.Route(options.Config.HTTP.Root, func(r chi.Router) {
		r.Get("/config.json", svc.Config)
		r.Mount("/", svc.Static())
	})

	return svc
}

// Phoenix defines implements the business logic for Service.
type Phoenix struct {
	logger    log.Logger
	config    *config.Config
	mux       *chi.Mux
	roleCache *roles.Cache
}

// ServeHTTP implements the Service interface.
func (p Phoenix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p Phoenix) getPayload(ctx context.Context) (payload []byte, err error) {
	cfg := p.loadRawConfig()
	cfgCopy := &config.PhoenixConfig{}
	err = copier.Copy(cfgCopy, cfg)
	if err != nil {
		p.logger.Error().Err(err).Msg("failed to make a deep copy of the config")
	}
	p.filterExternalApps(ctx, cfgCopy)
	return json.Marshal(cfgCopy)
}

func (p Phoenix) filterExternalApps(ctx context.Context, cfg *config.PhoenixConfig) {
	if !p.hasAccountManagementPermissions(ctx) {
		apps := make([]config.ExternalApp, 0)
		for _, app := range cfg.ExternalApps {
			if app.ID != "accounts" {
				apps = append(apps, app)
			}
		}
		if len(apps) != len(cfg.ExternalApps) {
			cfg.ExternalApps = apps
		}
	}
}

func (p Phoenix) loadRawConfig() *config.PhoenixConfig {
	// render dynamically using config
	if p.config.Phoenix.Path == "" {
		// provide default options
		if p.config.Phoenix.Config.Options == nil {
			p.config.Phoenix.Config.Options = make(map[string]interface{})
			p.config.Phoenix.Config.Options["hideSearchBar"] = true
		}

		// provide default external apps
		if p.config.Phoenix.Config.ExternalApps == nil {
			p.config.Phoenix.Config.ExternalApps = []config.ExternalApp{
				{
					ID:   "accounts",
					Path: "https://localhost:9200/accounts.js",
				},
				{
					ID:   "settings",
					Path: "https://localhost:9200/settings.js",
				},
			}
		}

		// make apps render as empty array if it is empty
		// TODO remove once https://github.com/golang/go/issues/27589 is fixed
		if len(p.config.Phoenix.Config.Apps) == 0 {
			p.config.Phoenix.Config.Apps = make([]string, 0)
		}

		return &p.config.Phoenix.Config
	}

	// try loading from file
	if _, err := os.Stat(p.config.Phoenix.Path); os.IsNotExist(err) {
		p.logger.Fatal().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("phoenix config doesn't exist")
	}

	payload, err := ioutil.ReadFile(p.config.Phoenix.Path)
	if err != nil {
		p.logger.Fatal().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("failed to read custom config")
	}

	cfg := &config.PhoenixConfig{}
	err = json.Unmarshal(payload, cfg)
	if err != nil {
		p.logger.Fatal().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("failed to parse custom config to json")
	}
	return cfg
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

	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

func (p Phoenix) hasAccountManagementPermissions(ctx context.Context) bool {
	// get roles from context
	roleIDs, ok := middleware.ReadRoleIDsFromContext(ctx)
	if !ok {
		// if there were no roleIDs the request was not authenticated or didn't go through ocis-proxy
		return false
	}

	// check if permission is present in roles of the authenticated account
	return p.roleCache.FindPermissionByID(roleIDs, asvc.AccountManagementPermissionID) != nil
}
