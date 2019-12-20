package svc

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/micro/go-micro/client/selector"
	"github.com/micro/go-micro/config/cmd"
	"github.com/micro/go-micro/registry"
	"github.com/micro/go-micro/registry/cache"
	"github.com/owncloud/ocis-phoenix/pkg/assets"
	"github.com/owncloud/ocis-phoenix/pkg/config"
	"github.com/owncloud/ocis-pkg/log"
)

var (
	re = regexp.MustCompile("^[a-zA-Z0-9]+([a-zA-Z0-9-]*[a-zA-Z0-9]*)?$")
	// ErrConfigInvalid is returned when the config parse is invalid.
	ErrConfigInvalid = `Invalid or missing config`
)

type reg struct {
	registry.Registry

	sync.Mutex
	lastPull time.Time
	services []*registry.Service
}

func (r *reg) watch() {
Loop:
	for {
		// get a watcher
		w, err := r.Registry.Watch()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		// loop results
		for {
			_, err := w.Next()
			if err != nil {
				w.Stop()
				time.Sleep(time.Second)
				goto Loop
			}

			// next pull will be from the registry
			r.Lock()
			r.lastPull = time.Time{}
			r.Unlock()
		}
	}
}

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

	// use the caching registry
	cache := cache.New((*cmd.DefaultOptions().Registry))
	reg := &reg{Registry: cache}

	// start the watcher
	go reg.watch()

	svc := Phoenix{
		logger:   options.Logger,
		config:   options.Config,
		mux:      m,
		registry: reg,
	}

	m.Route(options.Config.HTTP.Root, func(r chi.Router) {
		r.Get("/config.json", svc.Config)
		r.Mount("/apps/draw-io", svc.Static())
		r.Mount("/apps/files", svc.Static())
		r.Mount("/apps/markdown-editor", svc.Static())
		r.Mount("/apps/media-viewer", svc.Static())
		r.Mount("/apps/pdf-viewer", svc.Static())
		r.Mount("/apps/{service:[a-zA-Z0-9]+}", svc.Proxy())
		r.Mount("/", svc.Static())
	})

	return svc
}

// Phoenix defines implements the business logic for Service.
type Phoenix struct {
	logger   log.Logger
	config   *config.Config
	mux      *chi.Mux
	registry registry.Registry
}

// ServeHTTP implements the Service interface.
func (p Phoenix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

// Config implements the Service interface.
func (p Phoenix) Config(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(p.config.Phoenix.Path); os.IsNotExist(err) {
		p.logger.Error().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("Phoenix config doesn't exist")

		http.Error(w, ErrConfigInvalid, http.StatusUnprocessableEntity)
		return
	}

	payload, err := ioutil.ReadFile(p.config.Phoenix.Path)

	if err != nil {
		p.logger.Error().
			Err(err).
			Str("config", p.config.Phoenix.Path).
			Msg("Failed to read custom config")

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

// Proxy forwards requests to services using the registry
func (p Phoenix) Proxy() http.Handler {

	sel := selector.NewSelector(
		selector.Registry(p.registry),
	)

	director := func(r *http.Request) {
		kill := func() {
			r.URL.Host = ""
			r.URL.Path = ""
			r.URL.Scheme = ""
			r.Host = ""
			r.RequestURI = ""
		}

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 2 {
			kill()
			return
		}
		if !re.MatchString(parts[1]) {
			kill()
			return
		}
		next, err := sel.Select(p.config.Phoenix.Namespace + "." + parts[2]) // 1 is "apps"
		if err != nil {
			kill()
			return
		}

		s, err := next()
		if err != nil {
			kill()
			return
		}

		r.Header.Set( /*BasePathHeader*/ "X-Micro-Web-Base-Path", "/"+parts[2])
		r.URL.Host = s.Address
		r.URL.Path = "/" + strings.Join(parts[3:], "/")
		r.URL.Scheme = "http"
		r.Host = r.URL.Host
	}

	return &proxy{
		Default:  &httputil.ReverseProxy{Director: director},
		Director: director,
	}
}
