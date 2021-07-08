package caddyconsul

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// getAppFromParseCaddyfile instantiates a new App{} struct from a Cadddyfile
func getAppFromParseCaddyfile(d *caddyfile.Dispenser, existingVal interface{}) (interface{}, error) {

	app, err := parseCaddyfile(d, existingVal)
	if err != nil {
		return nil, err
	}

	return httpcaddyfile.App{
		Name:  "consul",
		Value: caddyconfig.JSON(app, nil),
	}, nil

}

// parseCaddyfile configures the "consul" global option from Caddyfile.
// Syntax:
//		consul {
//			consul_global_config_key <key>
//			consul_services_tag <tag>
//			use_request_id <bool>
//			consul_server {
//				...
//			}
//			default_http_server_options {
//				...
//			}
//			authentication_configuration {
//				...
//			}
//		}
func parseCaddyfile(d *caddyfile.Dispenser, _ interface{}) (*App, error) {

	app := NewApp()

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "consul_global_config_key":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.ConsulGlobalConfigKey = d.Val()
		case "consul_services_tag":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.ServicesTag = d.Val()
		case "use_request_id":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.UseRequestID = d.Val() == "true"
		case "consul_server":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "address":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Address = d.Val()
				case "scheme":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Scheme = d.Val()
				case "datacenter":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Datacenter = d.Val()
				case "namespace":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Namespace = d.Val()
				case "token":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Token = d.Val()
				case "token_file":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.TokenFile = d.Val()
				case "username":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Username = d.Val()
				case "password":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.Server.Password = d.Val()
				}
			}
		case "default_http_server_options":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "zone":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.DefaultHTTPServerOptions.Zone = d.Val()
				case "http_port":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					val, err := strconv.Atoi(d.Val())
					if err != nil {
						return nil, err
					}
					app.DefaultHTTPServerOptions.HTTPPort = val
				case "https_port":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					val, err := strconv.Atoi(d.Val())
					if err != nil {
						return nil, err
					}
					app.DefaultHTTPServerOptions.HTTPSPort = val
				}
			}

		case "tls_issuers":
			for nesting := d.Nesting(); d.NextBlock(nesting); {

				issuer := d.Val()
				module := fmt.Sprintf("tls.issuance.%s", issuer)

				unm, err := caddyfile.UnmarshalModule(d, module)
				if err != nil {
					return nil, err
				}

				app.TLSIssuers = append(app.TLSIssuers, caddyconfig.JSONModuleObject(unm, "module", issuer, nil))
			}

		case "authentication_configuration":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "enabled":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.AuthenticationConfiguration.Enabled = d.Val() == "true"
				case "authentication_domain":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.AuthenticationConfiguration.AuthenticationDomain = d.Val()
				case "custom_claims_headers":
					app.AuthenticationConfiguration.CustomClaimsHeaders = make(map[string]string)
					for nesting := d.Nesting(); d.NextBlock(nesting); {
						key := d.Val()
						if !d.NextArg() {
							return nil, d.ArgErr()
						}
						val := d.Val()
						app.AuthenticationConfiguration.CustomClaimsHeaders[key] = val
					}

				case "authp":
					unm, err := caddyfile.UnmarshalModule(d, "http.handlers.authp")
					if err != nil {
						return nil, err
					}
					jsonstr, err := json.Marshal(unm)
					if err != nil {
						return nil, err
					}
					err = json.Unmarshal(jsonstr, &app.AuthenticationConfiguration)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return app, nil
}
