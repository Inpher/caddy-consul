package caddyconsul

import (
	"encoding/json"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/hashicorp/consul/api"
	"github.com/pkg/errors"

	_ "github.com/greenpau/caddy-auth-jwt"
	_ "github.com/greenpau/caddy-auth-portal"
	_ "github.com/lolPants/caddy-requestid"
)

func init() {
	caddy.RegisterModule(App{})
}

var (
	lastIndexes    sync.Map
	globalInitDone bool
	globalConfig   *caddy.Config
	globalServices map[string][]*api.ServiceEntry
)

type App struct {
	UseRequestID                bool                         `json:"use_request_id"`
	ConsulGlobalConfigKey       string                       `json:"consul_global_config_key"`
	ServicesTag                 string                       `json:"consul_services_tag"`
	Server                      *ConsulServer                `json:"consul_server"`
	DefaultHTTPServerOptions    *DefaultHTTPServerOptions    `json:"default_http_server_options"`
	TLSIssuers                  []json.RawMessage            `json:"tls_issuers"`
	AuthenticationConfiguration *AuthenticationConfiguration `json:"authentication_configuration"`

	client         *api.Client
	globalConfig   *caddy.Config
	services       map[string][]*api.ServiceEntry
	fullConfigJSON []byte
	shutdownChan   chan bool
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "consul",
		New: func() caddy.Module { return new(App) },
	}
}

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

	if globalServices == nil {
		globalServices = make(map[string][]*api.ServiceEntry)
	}

	return nil
}

func (cc *App) Start() error {

	caddy.Log().Named("consul").Info("Starting app")

	// We init our Consul watcher
	go cc.watchConsul()

	return nil
}

func (cc *App) Stop() error {
	return nil
}

func (cc *App) Cleanup() error {

	caddy.Log().Named("consul").Info("Cleaning up app")
	cc.shutdownChan <- true

	return nil
}

var _ caddy.CleanerUpper = (*App)(nil)
