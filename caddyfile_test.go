package caddyconsul

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/greenpau/caddy-auth-portal/pkg/authn"
	"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	"github.com/stretchr/testify/require"
)

func TestParseCaddyfile(t *testing.T) {

	var testcases = []struct {
		name        string
		config_file string
		expectedApp *App
		err         error
	}{
		{
			name:        "simple",
			config_file: "assets/tests/caddyfile/basic.caddyfile",
			expectedApp: &App{
				ConsulGlobalConfigKey: "configs/caddy/caddyfile",
				Server: &ConsulServer{
					Address: "127.0.0.1:8500",
					Scheme:  "http",
				},
				AutoReverseProxy: &AutoReverseProxyOptions{
					TLSIssuers:               []json.RawMessage{},
					DefaultHTTPServerOptions: &DefaultHTTPServerOptions{},
					AuthenticationConfiguration: &AuthenticationConfiguration{
						AuthPortalConfiguration: authn.Authenticator{},
					},
				},
			},
		},
		{
			name:        "complex",
			config_file: "assets/tests/caddyfile/complete.caddyfile",
			expectedApp: &App{
				ConsulGlobalConfigKey: "configs/caddy/caddyfile",
				Server: &ConsulServer{
					Address: "127.0.0.1:8500",
					Scheme:  "http",
				},
				AutoReverseProxy: &AutoReverseProxyOptions{
					ServicesTag:  "caddy",
					UseRequestID: true,
					TLSIssuers: []json.RawMessage{[]byte(`{
						"challenges":{
							"dns":{
								"resolvers":["1.1.1.1"]
							},
							"http":{
								"alternate_port": 8080
							}
						},
						"module": "acme",
						"email": "sysadmin@example.com"
					}`)},
					DefaultHTTPServerOptions: &DefaultHTTPServerOptions{
						Zone:      "my-awesome-domain.io",
						HTTPPort:  80,
						HTTPSPort: 443,
					},
					AuthenticationConfiguration: &AuthenticationConfiguration{
						Enabled:              true,
						AuthenticationDomain: "auth.my-awesome-domain.io",
						CustomClaimsHeaders: map[string]string{
							"x-token-user-email": "X-MYCOMPANY-USER",
						},
						AuthPortalConfiguration: authn.Authenticator{
							CookieConfig: &cookie.Config{
								Domain: "my-awesome-domain.io",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			filecontent, err := ioutil.ReadFile(tc.config_file)
			if err != nil {
				require.Error(t, fmt.Errorf("Unable to read file %s", tc.config_file))
				return
			}

			d := caddyfile.NewTestDispenser(string(filecontent))

			app, err := parseCaddyfile(d, nil)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			require.Equal(t, tc.expectedApp.Server, app.Server, "unexpected consul_global_config_key")
			require.Equal(t, tc.expectedApp.ConsulGlobalConfigKey, app.ConsulGlobalConfigKey, "unexpected consul_server")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.UseRequestID, app.AutoReverseProxy.UseRequestID, "unexpected auto_reverse_proxy.use_request_id")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.ServicesTag, app.AutoReverseProxy.ServicesTag, "unexpected auto_reverse_proxy.consul_services_tag")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.DefaultHTTPServerOptions, app.AutoReverseProxy.DefaultHTTPServerOptions, "unexpected auto_reverse_proxy.default_http_server_options")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.AuthenticationConfiguration.Enabled, app.AutoReverseProxy.AuthenticationConfiguration.Enabled, "unexpected auto_reverse_proxy.authentication_configuration.enabled")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain, app.AutoReverseProxy.AuthenticationConfiguration.AuthenticationDomain, "unexpected auto_reverse_proxy.authentication_configuration.authentication_domain")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.AuthenticationConfiguration.CustomClaimsHeaders, app.AutoReverseProxy.AuthenticationConfiguration.CustomClaimsHeaders, "unexpected auto_reverse_proxy.authentication_configuration.custom_claims_headers")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.BackendConfigs, app.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.BackendConfigs, "unexpected auto_reverse_proxy.authentication_configuration.authp.backends")
			require.Equal(t, tc.expectedApp.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.CookieConfig, app.AutoReverseProxy.AuthenticationConfiguration.AuthPortalConfiguration.CookieConfig, "unexpected auto_reverse_proxy.authentication_configuration.authp.cookie domain")

			// Specific TLS issuers part, as input is []json.RawMessage
			require.Equal(t, len(tc.expectedApp.AutoReverseProxy.TLSIssuers), len(app.AutoReverseProxy.TLSIssuers), "unexpected quantity of auto_reverse_proxy.tls_issuers")

			if len(tc.expectedApp.AutoReverseProxy.TLSIssuers) > 0 {
				expectedTLSIssuers := &caddytls.ACMEIssuer{}
				actualTLSIssuers := &caddytls.ACMEIssuer{}

				err = json.Unmarshal(tc.expectedApp.AutoReverseProxy.TLSIssuers[0], expectedTLSIssuers)
				require.NoError(t, err, "unexpected value for expected auto_reverse_proxy.tls_issuers[0]: invalid JSON")
				err = json.Unmarshal(app.AutoReverseProxy.TLSIssuers[0], actualTLSIssuers)
				require.NoError(t, err, "unexpected value for auto_reverse_proxy.tls_issuers[0]: invalid JSON")

				require.Equal(t, expectedTLSIssuers, actualTLSIssuers, "unexpected value for auto_reverse_proxy.tls_issuers[0]")
			}
		})
	}

	return

}

func TestValidate(t *testing.T) {

	var testcases = []struct {
		name        string
		config      string
		expectedApp *App
		err         error
	}{
		{
			name: "error-consul-address-required",
			config: `consul {
				consul_global_config_key "configs/caddy/caddyfile"
				consul_server {
					scheme "http"
				}
			}`,
			err: ErrConsulServerAddressMissing,
		},
		{
			name: "error-consul-scheme-required",
			config: `consul {
				consul_global_config_key "configs/caddy/caddyfile"
				consul_server {
					address 127.0.0.1:8500
				}
			}`,
			err: ErrConsulServerSchemeMissing,
		},
		{
			name: "error-global-consul-kv-required",
			config: `consul {
				consul_server {
					address 127.0.0.1:8500
					scheme http
				}
			}`,
			err: ErrMissingConsulKVKey,
		},
		{
			name: "error-server-options-http-port",
			config: `consul {
				consul_global_config_key "configs/caddy/caddyfile"
				consul_server {
					address 127.0.0.1:8500
					scheme http
				}
				auto_reverse_proxy {
					consul_services_tag caddy
					default_http_server_options {
						https_port 443
						zone "test.com"
					}
				}
			}`,
			err: ErrMissingDefaultHTTPServerOptionsHTTPPort,
		},
		{
			name: "error-server-options-https-port",
			config: `consul {
				consul_global_config_key "configs/caddy/caddyfile"
				consul_server {
					address 127.0.0.1:8500
					scheme http
				}
				auto_reverse_proxy {
					consul_services_tag caddy
					default_http_server_options {
						http_port 80
						zone "test.com"
					}
				}
			}`,
			err: ErrMissingDefaultHTTPServerOptionsHTTPSPort,
		},
		{
			name: "error-server-options-zone",
			config: `consul {
				consul_global_config_key "configs/caddy/caddyfile"
				consul_server {
					address 127.0.0.1:8500
					scheme http
				}
				auto_reverse_proxy {
					consul_services_tag caddy
					default_http_server_options {
						http_port 80
						https_port 443
					}
				}
			}`,
			err: ErrMissingDefaultHTTPServerOptionsZone,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			d := caddyfile.NewTestDispenser(tc.config)

			app, _ := parseCaddyfile(d, nil)

			err := app.Validate()
			if tc.err == nil {
				require.EqualError(t, err, tc.err.Error(), "meow?")
			} else {
				require.EqualError(t, err, tc.err.Error(), "wuaf")
			}
		})
	}

}
