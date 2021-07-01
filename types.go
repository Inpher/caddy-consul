package caddyconsul

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	caddyauthjwtauth "github.com/greenpau/caddy-auth-jwt/pkg/auth"
	caddyauthportalcore "github.com/greenpau/caddy-auth-portal/pkg/core"
	"github.com/hashicorp/consul/api"
	caddyrequestid "github.com/lolPants/caddy-requestid"
)

type ConsulServer struct {
	Address    string `json:"address"`
	Scheme     string `json:"scheme"`
	Datacenter string `json:"datacenter"`
	Namespace  string `json:"namespace"`
	Token      string `json:"token"`
	TokenFile  string `json:"token_file"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type DefaultHTTPServerOptions struct {
	Zone      string `json:"zone"`
	HTTPPort  int    `json:"http_port"`
	HTTPSPort int    `json:"https_port"`
}

type DefaultTLSOptions struct {
	Resolvers          []string    `json:"resolvers"`
	Email              string      `json:"email"`
	TTL                int64       `json:"ttl"`
	PropagationTimeout int64       `json:"propagation_timeout"`
	Provider           interface{} `json:"provider"`
}

type AuthenticationConfiguration struct {
	Enabled                 bool                           `json:"enabled"`
	AuthenticationDomain    string                         `json:"authentication_domain"`
	AuthenticationPath      string                         `json:"authentication_path"`
	DefaultBackend          string                         `json:"default_backend"`
	CustomClaimsHeaders     map[string]string              `json:"custom_claims_headers"`
	AuthPortalConfiguration caddyauthportalcore.AuthPortal `json:"auth_portal_configuration"`
}

type AuthPortalConfiguration struct {
	Backends []map[string]string `json:"backends"`
	JWT      map[string]string   `json:"jwt"`
	Cookies  map[string]string   `json:"cookies"`
}

type SubdomainReverseProxyOptions struct {
	ZoneOverride             string `caddy:"zone=(.*)"`
	ServiceNameOverride      string `caddy:"name=(.*)"`
	NoHTTPS                  bool   `caddy:"no-https"`
	UpstreamHeaders          bool   `caddy:"upstream-headers"`
	LoadBalancingPolicy      string `caddy:"lb-policy=(.*)"`
	LoadBalancingTryDuration int    `caddy:"lb-try-duration=(.*)"`
	LoadBalancingTryInterval int    `caddy:"lb-try-interval=(.*)"`
	FlushInterval            int    `caddy:"flush-interval=(.*)"`
	BufferRequests           bool   `caddy:"buffer-requests"`
	BufferResponses          bool   `caddy:"buffer-responses"`
	MaxBufferSize            int    `caddy:"max-buffer-size=(.*)"`
	Authentication           bool   `caddy:"enable-auth"`
	AuthenticationProvider   string `caddy:"auth-backend=(.*)"`
}

type CaddyHTTPHandler caddyhttp.Handler

type ReverseProxyHandler struct {
	HandlerName string `json:"handler"`
	reverseproxy.Handler
}

func NewReverseProxyHandler() *ReverseProxyHandler {
	return &ReverseProxyHandler{
		HandlerName: "reverse_proxy",
	}
}

type ReverseProxyLoadBalancingSelection struct {
	Policy string `json:"policy"`
}

type AuthPortalHandler struct {
	HandlerName string                         `json:"handler"`
	Portal      caddyauthportalcore.AuthPortal `json:"portal"`
}

func NewAuthPortalHandler() *AuthPortalHandler {
	return &AuthPortalHandler{
		HandlerName: "auth_portal",
	}
}

type SubRouteHandler struct {
	HandlerName string `json:"handler"`
	caddyhttp.Subroute
}

func NewSubRouteHandler() *SubRouteHandler {
	return &SubRouteHandler{
		HandlerName: "subroute",
	}
}

type AuthenticationHandler struct {
	HandlerName string `json:"handler"`
	Providers   struct {
		JWT struct {
			Authorizer caddyauthjwtauth.Authorizer `json:"authorizer"`
		} `json:"jwt"`
	} `json:"providers"`
}

func NewAuthenticationHandler(authURLPath string) *AuthenticationHandler {
	authHandler := &AuthenticationHandler{
		HandlerName: "authentication",
	}
	if authURLPath != "" {
		authHandler.Providers.JWT.Authorizer.AuthURLPath = authURLPath
	}
	return authHandler
}

type RequestIDHandler struct {
	HandlerName string `json:"handler"`
	caddyrequestid.RequestID
}

func NewRequestIDHandler() *RequestIDHandler {
	return &RequestIDHandler{
		HandlerName: "request_id",
	}
}

type AcmeIssuer struct {
	Module string `json:"module"`
	caddytls.ACMEIssuer
}

type Hosts []string

type ServiceEntries struct {
	EventType string
	Service   string
	Entries   []*api.ServiceEntry
}
