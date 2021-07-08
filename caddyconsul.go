package caddyconsul

import (
	"encoding/json"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/hashicorp/consul/api"
	"github.com/pkg/errors"

	_ "github.com/greenpau/caddy-auth-jwt"
	_ "github.com/greenpau/caddy-auth-portal"
	_ "github.com/lolPants/caddy-requestid"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("consul", getAppFromParseCaddyfile)
}

// This variables are global to allow informations passing between two instances
// of the plugin new configuration reloads (which triggers a Stop()/Cleanup()
// of the previous instance of the plugin and Start()/Provision() a new one).
var (
	// lastIndexes is a sync.Map of the last requested Consul indexes
	lastIndexes sync.Map
	// globalConfig stores the config recovered from the Consul K/V store
	globalConfig *caddy.Config
	// globalServices stores the services to reverse-proxy
	globalServices map[string][]*api.ServiceEntry
	// globalInitDone states if it is safe to generate the config because
	// both the config and the services have been fetch once
	globalInitDone bool
)

// App is the main Consul plugin struct
type App struct {
	// Whether or not to add X-Request-ID headers in requests
	UseRequestID bool `json:"use_request_id"`
	// Consul config K/V store key
	ConsulGlobalConfigKey string `json:"consul_global_config_key"`
	// The Consul service tag that triggers reverse-proxying of the service
	ServicesTag string `json:"consul_services_tag" `
	// Information to reach the Consul server
	Server *ConsulServer `json:"consul_server"`
	// Default HTTP(s) server options
	DefaultHTTPServerOptions *DefaultHTTPServerOptions `json:"default_http_server_options"`
	// The TLS issuers to use when generating the Caddy TLS app configuration
	TLSIssuers []json.RawMessage `json:"tls_issuers" caddy:"namespace=tls.issuance inline_key=module"`
	// The authentication configuration
	AuthenticationConfiguration *AuthenticationConfiguration `json:"authentication_configuration"`

	client         *api.Client
	globalConfig   *caddy.Config
	services       map[string][]*api.ServiceEntry
	fullConfigJSON []byte
	shutdownChan   chan bool
}

// NewApp instantiates a new App{} struct
func NewApp() (app *App) {

	app = &App{
		Server:                      &ConsulServer{},
		DefaultHTTPServerOptions:    &DefaultHTTPServerOptions{},
		TLSIssuers:                  []json.RawMessage{},
		AuthenticationConfiguration: &AuthenticationConfiguration{},
	}

	return
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "consul",
		New: func() caddy.Module { return NewApp() },
	}
}

// Provision sets up the module.
func (cc *App) Provision(ctx caddy.Context) (err error) {

	caddy.Log().Named("consul").Info("Provisioning app")

	cc.shutdownChan = make(chan bool)

	// Initialize Consul client
	cc.client, err = api.NewClient(&api.Config{
		Address:    cc.Server.Address,
		Scheme:     cc.Server.Scheme,
		Datacenter: cc.Server.Datacenter,
		Namespace:  cc.Server.Namespace,
		Token:      cc.Server.Token,
		TokenFile:  cc.Server.TokenFile,
		HttpAuth: &api.HttpBasicAuth{
			Username: cc.Server.Username,
			Password: cc.Server.Password,
		},
	})
	if err != nil {
		err = errors.Wrap(err, "unable to initiate Consul client")
		return
	}

	// Init the global services map.
	// This map is shared accross all plugin's instances
	if globalServices == nil {
		globalServices = make(map[string][]*api.ServiceEntry)
	}

	return nil
}

// Start starts the module.
func (cc *App) Start() error {

	caddy.Log().Named("consul").Info("Starting app")

	// We init our Consul watcher
	go cc.watchConsul()

	return nil
}

// Stop stops the module.
func (cc *App) Stop() error {
	return nil
}

// Cleanup cleanups the module.
func (cc *App) Cleanup() error {

	caddy.Log().Named("consul").Info("Cleaning up app")
	cc.shutdownChan <- true
	caddy.Log().Named("consul").Info("App was cleaned!")

	return nil
}

// Validate validates that the module has a usable config.
func (cc *App) Validate() error {

	if cc.ConsulGlobalConfigKey == "" {
		return ErrMissingConsulKVKey
	}
	if cc.ServicesTag == "" {
		return ErrMissingConsulServiceTag
	}
	if cc.Server.Address == "" {
		return ErrConsulServerAddressMissing
	}
	if cc.Server.Scheme == "" {
		return ErrConsulServerSchemeMissing
	}

	return nil
}

// UnmarshalCaddyfile unmarshal plugin's caddyfile.
func (cc *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {

	app, err := parseCaddyfile(d, nil)
	if err != nil {
		return
	}

	cc = app

	return
}

// Interface guards
var (
	_ caddy.App             = (*App)(nil)
	_ caddy.Provisioner     = (*App)(nil)
	_ caddy.Validator       = (*App)(nil)
	_ caddy.CleanerUpper    = (*App)(nil)
	_ caddyfile.Unmarshaler = (*App)(nil)
)
