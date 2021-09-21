package caddyconsul

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/authz"
	portal "github.com/greenpau/caddy-auth-portal"
	caddyrequestid "github.com/lolPants/caddy-requestid"
)

// generateConfAsJSON is an easy accessor that calls generateConf,
// but returns its result as JSON
func (cc *App) generateConfAsJSON() (confJson []byte, err error) {

	conf, err := cc.generateConf()
	if err != nil {
		return
	}

	return caddyconfig.JSON(conf, nil), nil

}

// generateConf generates the Caddy configuration from the global K/V store
// and the services in Consul
func (cc *App) generateConf() (conf *caddy.Config, err error) {

	if globalConfig == nil {
		return conf, fmt.Errorf("globalConfig not initialized yet!")
	}

	conf = &*globalConfig

	err = cc.generateHTTPAndTLSAppConfFromConsulServices(conf)
	if err != nil {
		return
	}

	return
}

// generateHTTPAndTLSAppConfFromConsulServices handles the generation
// of the TLS and HTTP Caddy apps
func (cc *App) generateHTTPAndTLSAppConfFromConsulServices(conf *caddy.Config) (err error) {

	if len(globalServices) == 0 {
		return
	}

	services := globalServices

	if conf.AppsRaw == nil {
		conf.AppsRaw = make(caddy.ModuleMap)
	}

	// We create two servers while generating the HTTP app config:
	// - http handles the HTTP only websites
	// - https handles the HTTPS websites
	httpConf := &caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"http": {
				Listen: []string{
					fmt.Sprintf(":%d", cc.AutoReverseProxy.DefaultHTTPServerOptions.HTTPPort),
				},
				Routes: caddyhttp.RouteList{},
			},
			"https": {
				Listen: []string{
					fmt.Sprintf(":%d", cc.AutoReverseProxy.DefaultHTTPServerOptions.HTTPSPort),
				},
				Routes: caddyhttp.RouteList{cc.getAuthRoute()},
			},
		},
	}

	// We also generate the TLS app config
	tlsConf := &caddytls.TLS{
		Automation: &caddytls.AutomationConfig{
			Policies: []*caddytls.AutomationPolicy{},
		},
	}

	// If the authentication is enabled, we need to handle the certificates for the authentication domain too
	if cc.AutoReverseProxy.AuthenticationConfiguration.Enabled {
		tlsConf.Automation.Policies = append(tlsConf.Automation.Policies, &caddytls.AutomationPolicy{
			Subjects:   []string{cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain},
			IssuersRaw: cc.AutoReverseProxy.TLSIssuers,
		})
	}

	// We iterate on every Consul service
	for _, instances := range services {

		// If no instance (AKA upstream) was returned, let's continue
		if len(instances) == 0 {
			continue
		}

		// We compute the upstreams and options requested from the service's instances
		upstreams, options := parseConsulService(instances)

		// Let's start by instantiating the reverse-proxy handler
		reverseProxyHandler := &reverseproxy.Handler{
			Upstreams:       upstreams,
			FlushInterval:   caddy.Duration(options.FlushInterval),
			BufferRequests:  options.BufferRequests,
			BufferResponses: options.BufferResponses,
			MaxBufferSize:   int64(options.MaxBufferSize),
			Headers: &headers.Handler{
				Request: &headers.HeaderOps{Add: http.Header{}},
				Response: &headers.RespHeaderOps{
					Deferred:  true,
					HeaderOps: &headers.HeaderOps{Add: http.Header{}},
				},
			},
		}

		// If Upstream is HTTPS, then we use HTTPTransport and add the TLS tag (insecure)
		if options.UpstreamScheme == "https" {
			transport := reverseproxy.HTTPTransport{
				TLS: &reverseproxy.TLSConfig{
					InsecureSkipVerify: true,
				},
			}
			reverseProxyHandler.TransportRaw = caddyconfig.JSON(transport, nil)
		}

		// Do we propagate upstream headers?
		if options.UpstreamHeaders {
			reverseProxyHandler.Headers.Response.Add = http.Header{
				"X-PROXY-UPSTREAM-ADDRESS":  []string{"{http.reverse_proxy.upstream.address}"},
				"X-PROXY-UPSTREAM-LATENCY":  []string{"{http.reverse_proxy.upstream.latency}"},
				"X-PROXY-UPSTREAM-DURATION": []string{"{http.reverse_proxy.upstream.duration}"},
				"X-PROXY-DURATION":          []string{"{http.reverse_proxy.duration}"},
			}
		}

		// If authentication is enabled, let's remap the JWT claims
		if cc.AutoReverseProxy.AuthenticationConfiguration.Enabled && options.Authentication {
			for header, customHeader := range cc.AutoReverseProxy.AuthenticationConfiguration.CustomClaimsHeaders {
				if _, ok := reverseProxyHandler.Headers.Request.Add[customHeader]; !ok {
					reverseProxyHandler.Headers.Request.Add[customHeader] = []string{}
				}
				reverseProxyHandler.Headers.Request.Add[customHeader] = append(
					reverseProxyHandler.Headers.Request.Add[customHeader],
					fmt.Sprintf("{http.request.header.%s}", header),
				)

				if _, ok := reverseProxyHandler.Headers.Response.Add[customHeader]; !ok {
					reverseProxyHandler.Headers.Response.Add[customHeader] = []string{}
				}
				reverseProxyHandler.Headers.Response.Add[customHeader] = append(
					reverseProxyHandler.Headers.Response.Add[customHeader],
					fmt.Sprintf("{http.request.header.%s}", header),
				)
			}
		}

		// Do we want to use the request-id module?
		if cc.AutoReverseProxy.UseRequestID {
			reverseProxyHandler.Headers.Request.Add["X-REQUEST-ID"] = []string{"{http.request_id}"}
			reverseProxyHandler.Headers.Response.Add["X-REQUEST-ID"] = []string{"{http.request_id}"}
		}

		// Do we have a specific load-balancing policy attached?
		if options.LoadBalancingPolicy != "" {
			reverseProxyHandler.LoadBalancing = &reverseproxy.LoadBalancing{
				SelectionPolicyRaw: caddyconfig.JSON(map[string]string{"policy": options.LoadBalancingPolicy}, nil),
			}
		}

		// Is our service HTTP only?
		servers := []string{"https"}
		if options.NoHTTPS {
			servers = []string{"http"}
		} else if options.NoAutoHTTPSRedirect {
			servers = append(servers, "http")
		}

		// Let's define the host name for the service
		name := instances[0].Service.Service
		zone := cc.AutoReverseProxy.DefaultHTTPServerOptions.Zone
		if options.ServiceNameOverride != "" {
			name = options.ServiceNameOverride
		}
		if options.ZoneOverride != "" {
			zone = options.ZoneOverride
		}

		// We now have the hostname we want to use
		hostnames := []string{fmt.Sprintf("%s.%s", name, zone)}

		// Let's prepare the TLS app part for this website
		tlsConf.Automation.Policies = append(tlsConf.Automation.Policies, &caddytls.AutomationPolicy{
			Subjects:   hostnames,
			IssuersRaw: cc.AutoReverseProxy.TLSIssuers,
		})

		// And now, let's build the handlers!
		handlersRaw := []json.RawMessage{}

		// If we have authentication, we need to add the caddy-auth-jwt handler
		if options.Authentication {
			authURLPath := fmt.Sprintf(
				"https://%s/auth",
				cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain,
			)
			if options.AuthenticationProvider != "" {
				authURLPath = fmt.Sprintf(
					"https://%s/auth/%s",
					cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain,
					options.AuthenticationProvider,
				)
			}
			handlersRaw = append(handlersRaw, caddyconfig.JSON(NewAuthenticationHandler(authURLPath), nil))
		}

		// If we generate (or propagate) the X-Request-ID header, we need to add the request_id handler
		if cc.AutoReverseProxy.UseRequestID {
			handlersRaw = append(handlersRaw, caddyconfig.JSONModuleObject(caddyrequestid.RequestID{}, "handler", "request_id", nil))
		}

		// And finally, we add the reverse_proxy handler!
		handlersRaw = append(handlersRaw, caddyconfig.JSONModuleObject(reverseProxyHandler, "handler", "reverse_proxy", nil))

		// Now that we have everything, we add the route to our host on the relevant server (HTTP or HTTPS)
		for _, server := range servers {
			httpConf.Servers[server].Routes = append(httpConf.Servers[server].Routes,
				caddyhttp.Route{
					HandlersRaw: handlersRaw,
					MatcherSetsRaw: caddyhttp.RawMatcherSets{
						caddy.ModuleMap{
							"host": caddyconfig.JSON(hostnames, nil),
						},
					},
					Terminal: true,
				},
			)
		}

	}

	// As we finished iterating on all Consul services, we generated both HTTP and TLS apps config,
	// so we just need to push them to our config, and we're done!
	conf.AppsRaw["http"] = caddyconfig.JSON(httpConf, nil)
	conf.AppsRaw["tls"] = caddyconfig.JSON(tlsConf, nil)

	return
}

// getAuthRoute generates the HTTPS entry for the caddy-auth-portal plugin.
// It uses the value `AuthenticationConfiguration.AuthenticationDomain`
// to expose the auth portal on https://[AuthenticationConfiguration.AuthenticationDomain]/auth.
// It also setups a catch-all authenticated route to instantiate the primary caddy-auth-jwt
// plugin.
func (cc *App) getAuthRoute() (route caddyhttp.Route) {

	if !cc.AutoReverseProxy.AuthenticationConfiguration.Enabled {
		return
	}

	authMiddleware := &portal.AuthMiddleware{
		Portal: &cc.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration,
	}
	defaultAuthHandler := NewAuthenticationHandler(fmt.Sprintf(
		"https://%s/auth",
		cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain,
	))
	defaultAuthHandler.Providers.JWT.Authorizer = authz.Authorizer{
		AuthURLPath: fmt.Sprintf(
			"https://%s/auth",
			cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain,
		),
		PrimaryInstance:       true,
		PassClaimsWithHeaders: true,
		CryptoKeyConfigs:      cc.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.CryptoKeyConfigs,
		AccessListRules: []*acl.RuleConfiguration{
			{
				Conditions: []string{"always match roles any"},
				Action:     "allow",
			},
		},
	}

	subRouteHandler := &caddyhttp.Subroute{
		Routes: caddyhttp.RouteList{
			caddyhttp.Route{
				Terminal: true,
				MatcherSetsRaw: caddyhttp.RawMatcherSets{
					caddy.ModuleMap{
						"path_regexp": caddyconfig.JSON(caddyhttp.MatchPathRE{MatchRegexp: caddyhttp.MatchRegexp{Pattern: fmt.Sprintf("/auth*")}}, nil),
					},
				},
				HandlersRaw: []json.RawMessage{
					caddyconfig.JSONModuleObject(authMiddleware, "handler", "authp", nil),
				},
			},
			caddyhttp.Route{
				HandlersRaw: []json.RawMessage{caddyconfig.JSON(defaultAuthHandler, nil)},
			},
		},
	}

	route = caddyhttp.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{
				"host": caddyconfig.JSON([]string{cc.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain}, nil),
			},
		},
		HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(subRouteHandler, "handler", "subroute", nil)},
	}

	return
}
