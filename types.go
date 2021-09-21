package caddyconsul

import (
	"encoding/json"

	caddyauthjwtauth "github.com/greenpau/caddy-auth-jwt/pkg/authz"
	caddyauthportalauthn "github.com/greenpau/caddy-auth-portal/pkg/authn"
	"github.com/hashicorp/consul/api"
)

// ConsulServer represents the information to connect to the Consul server
type ConsulServer struct {
	// Address is the address of the Consul server
	Address string `json:"address"`

	// Scheme is the URI scheme for the Consul server
	Scheme string `json:"scheme"`

	// Datacenter to use. If not provided, the default agent datacenter is used.
	Datacenter string `json:"datacenter"`

	// Namespace is the name of the namespace to send along for the request
	// when no other Namespace is present in the QueryOptions
	Namespace string `json:"namespace"`

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string `json:"token"`

	// TokenFile is a file containing the current token to use for this client.
	// If provided it is read once at startup and never again.
	TokenFile string `json:"token_file"`

	// Username to use for HTTP Basic Authentication.
	Username string `json:"username"`

	// Password to use for HTTP Basic Authentication.
	Password string `json:"password"`
}

type AutoReverseProxyOptions struct {
	// UseRequestID describes whether or not to add X-Request-ID headers in requests
	UseRequestID bool `json:"use_request_id"`

	// ServicesTag is the Consul service tag that triggers reverse-proxying of the service
	ServicesTag string `json:"consul_services_tag" `

	// DefaultHTTPServerOptions describes the default HTTP(s) server options
	DefaultHTTPServerOptions *DefaultHTTPServerOptions `json:"default_http_server_options"`

	// TLSIssuers describes the TLS issuers to use when generating the Caddy TLS app configuration
	TLSIssuers []json.RawMessage `json:"tls_issuers" caddy:"namespace=tls.issuance inline_key=module"`

	// AuthenticationConfiguration describes the authentication configuration
	AuthenticationConfiguration *AuthenticationConfiguration `json:"authentication_configuration"`
}

// DefaultHTTPServerOptions describes the default HTTP(s) server options
type DefaultHTTPServerOptions struct {
	// Zone is the default zone used when generating reverse-proxy addresses
	Zone string `json:"zone"`

	// HTTPPort is the HTTP port used during the Caddy config generation
	HTTPPort int `json:"http_port"`

	// HTTPSPort is the HTTPS port used during the Caddy config generation
	HTTPSPort int `json:"https_port"`
}

// AuthenticationConfiguration describes the authentication configuration
type AuthenticationConfiguration struct {
	// Enabled describes whether or not authentication is globally enabled.
	// Each Consul service must also have a `caddy:enable-auth` tag
	// to have authentication enabled
	Enabled bool `json:"enabled"`

	// AuthenticationDomain represents the domain used for the authentication portal
	// (e.g. sso.my-company.com)
	AuthenticationDomain string `json:"authentication_domain"`

	// CustomClaimsHeaders represents the caddy-auth-jwt JWT claims
	// to remap to custom headers.
	// (e.g.: CustomClaimsHeaders["x-token-user-email"] = "X-MYCOMPANY-USER")
	CustomClaimsHeaders map[string]string `json:"custom_claims_headers"`

	// AuthPortalConfiguration is a perfect embedding
	// of caddy-auth-portal's configuration
	AuthPortalConfiguration caddyauthportalauthn.Authenticator `json:"authp"`
}

// SubdomainReverseProxyOptions describes the supported option tags
// for Consul services.
type SubdomainReverseProxyOptions struct {
	// ZoneOverride overrides DefaultHTTPServerOptions.Zone for the service
	ZoneOverride string `caddy:"zone=(.*)"`

	// ServiceNameOverride uses the provided name instead of the Consul service name
	ServiceNameOverride string `caddy:"name=(.*)"`

	// Disables auto-https on the service (will only resolve in HTTP)
	NoHTTPS bool `caddy:"no-https"`

	// Disables auto-https redirect on the service (will resolve both in HTTP and HTTPS)
	NoAutoHTTPSRedirect bool `caddy:"no-auto-https-redirect"`

	// Disables auto-https on the service (will only resolve in HTTP)
	UpstreamsScheme string `caddy:"upstreams-scheme=(.*)"`

	// Insecure on HTTPS scheme
	InsecureTLSUpstreams bool `caddy:"insecure-tls-upstreams"`

	// UpstreamHeaders defines whether or not to propagate the following upstream headers
	// in the request's response:
	// - X-PROXY-UPSTREAM-ADDRESS: address of the upstream server used
	// - X-PROXY-UPSTREAM-LATENCY: latency of the used upstream server
	// - X-PROXY-UPSTREAM-DURATION: used upstream server's request duration
	// - X-PROXY-DURATION: total duration of the proxying process
	UpstreamHeaders bool `caddy:"upstream-headers"`

	// LoadBalancingPolicy defines the load balancing policy to used for reverse-proxy,
	// as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#load-balancing
	// Only the options with no arguments are supported as of today.
	LoadBalancingPolicy string `caddy:"lb-policy=(.*)"`

	// LoadBalancingTryDuration defines the load balancing try duration,
	// as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#load-balancing
	LoadBalancingTryDuration int `caddy:"lb-try-duration=(.*)"`

	// LoadBalancingTryInterval defines the load balancing try interval,
	// as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#load-balancing
	LoadBalancingTryInterval int `caddy:"lb-try-interval=(.*)"`

	// FlushInterval defines the flush interval, as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming
	FlushInterval int `caddy:"flush-interval=(.*)"`

	// BufferRequests defines whether or not to buffer requests, as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming
	BufferRequests bool `caddy:"buffer-requests"`

	// BufferResponses defines whether or not to buffer responses, as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming
	BufferResponses bool `caddy:"buffer-responses"`

	// MaxBufferSize defines the max buffer size, as defined here:
	// https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming
	MaxBufferSize int `caddy:"max-buffer-size=(.*)"`

	// Authentication defines whether or not to handle authentication
	// before reverse-proxying for the specific service
	Authentication bool `caddy:"enable-auth"`

	// AuthenticationProvider is an optional value that defines the provider
	// to use in the redirection to the caddy-auth-portal (e.g. `oauth2/google`, `oauth2/github`, ...).
	// If no valid JWT is found, and this option is, for example set to `oauth2/google`,
	// the user will be redirected to:
	// https://AuthenticationConfiguration.AuthenticationDomain/auth/oauth2/google
	AuthenticationProvider string `caddy:"auth-backend=(.*)"`
}

// AuthenticationHandler is wrapper around caddy-auth-jwt authentication provider
type AuthenticationHandler struct {
	HandlerName string `json:"handler"`
	Providers   struct {
		JWT struct {
			Authorizer caddyauthjwtauth.Authorizer `json:"authorizer"`
		} `json:"jwt"`
	} `json:"providers"`
}

// NewAuthenticationHandler is an easy accessor to create a new isntance
// of NewAuthenticationHandler
func NewAuthenticationHandler(authURLPath string) *AuthenticationHandler {
	authHandler := &AuthenticationHandler{
		HandlerName: "authentication",
	}
	if authURLPath != "" {
		authHandler.Providers.JWT.Authorizer.AuthURLPath = authURLPath
	}
	return authHandler
}

// StandardError is a wrapper around string to handle the plugin's custom errors
type StandardError string

// Error returns the error as a string
func (e StandardError) Error() string {
	return string(e)
}

const (
	// ErrMissingConsulKVKey the Consul global config K/V is missing from the configuration
	ErrMissingConsulKVKey StandardError = "consul_global_config_key is missing"

	// ErrConsulServerAddressMissing the Consul address is missing from the configuration
	ErrConsulServerAddressMissing StandardError = "consul_server.address is missing"

	// The Consul scheme is missing from the configuration
	ErrConsulServerSchemeMissing StandardError = "consul_server.scheme is missing"

	// ErrMissingDefaultHTTPServerOptionsHTTPPort the HTTP port is missing
	ErrMissingDefaultHTTPServerOptionsHTTPPort StandardError = "auto_reverse_proxy.default_http_server_options.http_port is missing"

	// ErrMissingDefaultHTTPServerOptionsHTTPSPort the HTTPS port is missing
	ErrMissingDefaultHTTPServerOptionsHTTPSPort StandardError = "auto_reverse_proxy.default_http_server_options.https_port is missing"

	// ErrMissingDefaultHTTPServerOptionsZone the default zone is missing
	ErrMissingDefaultHTTPServerOptionsZone StandardError = "auto_reverse_proxy.default_http_server_options.zone is missing"

	// ErrMissingAuthenticationConfigurationAuthenticationDomain the authentication domain is missing
	ErrMissingAuthenticationConfigurationAuthenticationDomain StandardError = "authentication_configuration.authentication_domain"

	// ErrMissingAuthenticationConfigurationAuthPortalConfigurationBackendConfigs empty authportal backends
	ErrMissingAuthenticationConfigurationAuthPortalConfigurationBackendConfigs StandardError = "authentication_configuration.authp.backend_configs is empty"

	// ErrMissingAuthenticationConfigurationAuthPortalConfigurationCookieConfigDomain authportal cookie domain is missing
	ErrMissingAuthenticationConfigurationAuthPortalConfigurationCookieConfigDomain StandardError = "authentication_configuration.authp.cookie_config.domain is empty"
)

// ServiceEntries describes a Consul service for the internal computing
// of the services
type serviceEntries struct {
	EventType string
	Service   string
	Entries   []*api.ServiceEntry
}
