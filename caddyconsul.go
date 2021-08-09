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

	// ConsulGlobalConfigKey is the Consul config K/V store key
	ConsulGlobalConfigKey string `json:"consul_global_config_key"`

	// Server describes the information to reach the Consul server
	Server *ConsulServer `json:"consul_server"`

	// AutoReverseProxy describes the auto reverse-proxying configuration from Consul services
	AutoReverseProxy *AutoReverseProxyOptions `json:"auto_reverse_proxy"`

	client         *api.Client
	globalConfig   *caddy.Config
	services       map[string][]*api.ServiceEntry
	fullConfigJSON []byte
	shutdownChan   chan bool
}

// NewApp instantiates a new App{} struct
func NewApp() (app *App) {

	app = &App{
		Server: &ConsulServer{},
		AutoReverseProxy: &AutoReverseProxyOptions{
			DefaultHTTPServerOptions:    &DefaultHTTPServerOptions{},
			TLSIssuers:                  []json.RawMessage{},
			AuthenticationConfiguration: &AuthenticationConfiguration{
				// AuthPortalConfiguration: authn.Authenticator{
				// 	PrimaryInstance:        true,
				// 	Context:                "default",
				// 	UI:                     &ui.Parameters{},
				// 	UserRegistrationConfig: &registration.Config{},
				// 	TokenValidatorOptions:  &options.TokenValidatorOptions{},
				// },
			},
		},
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

	caddy.Log().Named("consul").Info("App is provisioned")

	return nil
}

// Start starts the module.
func (cc *App) Start() error {

	caddy.Log().Named("consul").Info("Starting app")

	// We start listening for shutdown events
	cc.shutdownChan = make(chan bool)

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
	if cc.shutdownChan != nil {
		cc.shutdownChan <- true
	}
	caddy.Log().Named("consul").Info("App was cleaned!")

	return nil
}

// Validate validates that the module has a usable config.
func (cc *App) Validate() error {

	caddy.Log().Named("consul").Info("Validating app")

	if cc.ConsulGlobalConfigKey == "" {
		return logAndReturn(ErrMissingConsulKVKey)
	}
	if cc.Server.Address == "" {
		return logAndReturn(ErrConsulServerAddressMissing)
	}
	if cc.Server.Scheme == "" {
		return logAndReturn(ErrConsulServerSchemeMissing)
	}

	// If ServicesTag is not empty, we will generate the http configuration,
	// so we need to have some information
	if cc.AutoReverseProxy.ServicesTag != "" {
		if cc.AutoReverseProxy.DefaultHTTPServerOptions.HTTPPort == 0 {
			return logAndReturn(ErrMissingDefaultHTTPServerOptionsHTTPPort)
		}
		if cc.AutoReverseProxy.DefaultHTTPServerOptions.HTTPSPort == 0 {
			return logAndReturn(ErrMissingDefaultHTTPServerOptionsHTTPSPort)
		}
		if cc.AutoReverseProxy.DefaultHTTPServerOptions.Zone == "" {
			return logAndReturn(ErrMissingDefaultHTTPServerOptionsZone)
		}
	}

	// If module caddy-auth-portal is enabled, some options are required
	if cc.AutoReverseProxy.AuthenticationConfiguration.Enabled {

		// If we handle authentication, we need to have an authentication domain
		if cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain == "" {
			return logAndReturn(ErrMissingAuthenticationConfigurationAuthenticationDomain)
		}

		// If we handle authentication, we need to have some backend configs
		if len(cc.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.BackendConfigs) == 0 {
			return logAndReturn(ErrMissingAuthenticationConfigurationAuthPortalConfigurationBackendConfigs)
		}

		// If we handle authentication, we need to have a domain for the cookie
		if cc.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.CookieConfig.Domain == "" {
			return logAndReturn(ErrMissingAuthenticationConfigurationAuthPortalConfigurationCookieConfigDomain)
		}
	}

	caddy.Log().Named("consul").Info("App validated")

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
