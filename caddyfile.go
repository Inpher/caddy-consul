package caddyconsul

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/greenpau/caddy-auth-jwt/pkg/auth"
	"github.com/greenpau/caddy-auth-jwt/pkg/config"
)

func (cc *App) generateConfAsJSON() (confJson []byte, err error) {

	conf, err := cc.generateConf()
	if err != nil {
		return
	}

	return asJSON(conf), nil

}

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

func (cc *App) generateHTTPAndTLSAppConfFromConsulServices(conf *caddy.Config) (err error) {

	if len(globalServices) == 0 {
		return
	}

	services := globalServices

	if conf.AppsRaw == nil {
		conf.AppsRaw = make(caddy.ModuleMap)
	}

	httpConf := &caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"http": {
				Listen: []string{
					fmt.Sprintf(":%d", cc.DefaultHTTPServerOptions.HTTPPort),
				},
				Routes: caddyhttp.RouteList{},
			},
			"https": {
				Listen: []string{
					fmt.Sprintf(":%d", cc.DefaultHTTPServerOptions.HTTPSPort),
				},
				Routes: caddyhttp.RouteList{cc.getAuthRoute()},
			},
		},
	}

	tlsConf := &caddytls.TLS{
		Automation: &caddytls.AutomationConfig{
			Policies: []*caddytls.AutomationPolicy{},
		},
	}

	if cc.AuthenticationConfiguration.Enabled {
		tlsConf.Automation.Policies = append(tlsConf.Automation.Policies, &caddytls.AutomationPolicy{
			Subjects:   Hosts{cc.AuthenticationConfiguration.AuthenticationDomain},
			IssuersRaw: cc.TLSIssuers,
		})
	}

	for _, instances := range services {

		// If no instance was returned, let's continue
		if len(instances) == 0 {
			continue
		}

		// We compute the upstreams and options requested from the service's instances
		upstreams, options := parseConsulService(instances)

		reverseProxyHandler := NewReverseProxyHandler()
		reverseProxyHandler.Upstreams = upstreams
		reverseProxyHandler.FlushInterval = caddy.Duration(options.FlushInterval)
		reverseProxyHandler.BufferRequests = options.BufferRequests
		reverseProxyHandler.BufferResponses = options.BufferResponses
		reverseProxyHandler.MaxBufferSize = int64(options.MaxBufferSize)
		reverseProxyHandler.Headers = &headers.Handler{
			Request: &headers.HeaderOps{Add: http.Header{}},
			Response: &headers.RespHeaderOps{
				Deferred:  true,
				HeaderOps: &headers.HeaderOps{Add: http.Header{}},
			},
		}

		if options.UpstreamHeaders {
			reverseProxyHandler.Headers.Response.Add = http.Header{
				"X-PROXY-UPSTREAM-ADDRESS":  []string{"{http.reverse_proxy.upstream.address}"},
				"X-PROXY-UPSTREAM-LATENCY":  []string{"{http.reverse_proxy.upstream.latency}"},
				"X-PROXY-UPSTREAM-DURATION": []string{"{http.reverse_proxy.upstream.duration}"},
				"X-PROXY-DURATION":          []string{"{http.reverse_proxy.duration}"},
			}
		}
		if cc.AuthenticationConfiguration.Enabled && options.Authentication {
			for header, customHeader := range cc.AuthenticationConfiguration.CustomClaimsHeaders {
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
		if cc.UseRequestID {
			reverseProxyHandler.Headers.Request.Add["X-REQUEST-ID"] = []string{"{http.request_id}"}
			reverseProxyHandler.Headers.Response.Add["X-REQUEST-ID"] = []string{"{http.request_id}"}
		}
		if options.LoadBalancingPolicy != "" {
			reverseProxyHandler.LoadBalancing = &reverseproxy.LoadBalancing{
				SelectionPolicyRaw: asJSON(ReverseProxyLoadBalancingSelection{Policy: options.LoadBalancingPolicy}),
			}
		}

		// // We iterate over all instances of the service
		// // to push the reverse_proxy upstreams
		// for _, instance := range instances {
		// 	reverseProxyHandler.Upstreams = append(reverseProxyHandler.Upstreams, &reverseproxy.Upstream{
		// 		Dial: fmt.Sprintf("%s:%d", instance.Service.Address, instance.Service.Port),
		// 	})
		// }

		name := instances[0].Service.Service
		zone := cc.DefaultHTTPServerOptions.Zone
		if options.ServiceNameOverride != "" {
			name = options.ServiceNameOverride
		}
		if options.ZoneOverride != "" {
			zone = options.ZoneOverride
		}
		hostnames := Hosts{fmt.Sprintf("%s.%s", name, zone)}

		tlsConf.Automation.Policies = append(tlsConf.Automation.Policies, &caddytls.AutomationPolicy{
			Subjects:   hostnames,
			IssuersRaw: cc.TLSIssuers,
		})

		server := "https"
		if options.NoHTTPS {
			server = "http"
		}

		handlersRaw := []json.RawMessage{}
		if options.Authentication {
			authURLPath := fmt.Sprintf(
				"https://%s%s/%s",
				cc.AuthenticationConfiguration.AuthenticationDomain,
				cc.AuthenticationConfiguration.AuthPortalConfiguration.AuthURLPath,
				cc.AuthenticationConfiguration.DefaultBackend,
			)
			if options.AuthenticationProvider != "" {
				authURLPath = fmt.Sprintf(
					"https://%s%s/%s",
					cc.AuthenticationConfiguration.AuthenticationDomain,
					cc.AuthenticationConfiguration.AuthPortalConfiguration.AuthURLPath,
					options.AuthenticationProvider,
				)
			}
			handlersRaw = append(handlersRaw, asJSON(NewAuthenticationHandler(authURLPath)))
		}
		if cc.UseRequestID {
			handlersRaw = append(handlersRaw, asJSON(NewRequestIDHandler()))
		}
		handlersRaw = append(handlersRaw, asJSON(reverseProxyHandler))

		httpConf.Servers[server].Routes = append(httpConf.Servers[server].Routes,
			caddyhttp.Route{
				HandlersRaw: handlersRaw,
				MatcherSetsRaw: caddyhttp.RawMatcherSets{
					caddy.ModuleMap{
						"host": asJSON(hostnames),
					},
				},
				Terminal: true,
			},
		)
	}

	conf.AppsRaw["http"] = asJSON(httpConf)
	conf.AppsRaw["tls"] = asJSON(tlsConf)

	return
}

func (cc *App) getAuthRoute() (route caddyhttp.Route) {

	if !cc.AuthenticationConfiguration.Enabled {
		return
	}

	subRouteHandler := NewSubRouteHandler()
	authPortalHandler := NewAuthPortalHandler()
	defaultAuthHandler := NewAuthenticationHandler(fmt.Sprintf(
		"https://%s%s/%s",
		cc.AuthenticationConfiguration.AuthenticationDomain,
		cc.AuthenticationConfiguration.AuthPortalConfiguration.AuthURLPath,
		cc.AuthenticationConfiguration.DefaultBackend,
	))
	authPortalHandler.Portal = cc.AuthenticationConfiguration.AuthPortalConfiguration
	defaultAuthHandler.Providers.JWT.Authorizer = auth.Authorizer{
		AuthURLPath: fmt.Sprintf(
			"https://%s%s/%s",
			cc.AuthenticationConfiguration.AuthenticationDomain,
			cc.AuthenticationConfiguration.AuthPortalConfiguration.AuthURLPath,
			cc.AuthenticationConfiguration.DefaultBackend,
		),
		PrimaryInstance:       true,
		PassClaimsWithHeaders: true,
		TrustedTokens: []*config.CommonTokenConfig{
			cc.AuthenticationConfiguration.AuthPortalConfiguration.TokenProvider,
		},
	}

	subRouteHandler.Routes = caddyhttp.RouteList{
		caddyhttp.Route{
			Terminal: true,
			MatcherSetsRaw: caddyhttp.RawMatcherSets{
				caddy.ModuleMap{
					"path_regexp": asJSON(caddyhttp.MatchPathRE{MatchRegexp: caddyhttp.MatchRegexp{Pattern: fmt.Sprintf("%s*", cc.AuthenticationConfiguration.AuthPortalConfiguration.AuthURLPath)}}),
				},
			},
			HandlersRaw: []json.RawMessage{asJSON(authPortalHandler)},
		},
		caddyhttp.Route{
			HandlersRaw: []json.RawMessage{asJSON(defaultAuthHandler)},
		},
	}

	route = caddyhttp.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{
				"host": asJSON(Hosts{cc.AuthenticationConfiguration.AuthenticationDomain}),
			},
		},
		HandlersRaw: []json.RawMessage{asJSON(subRouteHandler)},
	}

	return
}
