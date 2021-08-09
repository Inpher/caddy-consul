package caddyconsul

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/hashicorp/consul/api"
)

// getLastIndex is a function that takes an error as input and returns it after
// logging it via caddy.Log().Error()
func logAndReturn(err error) error {
	caddy.Log().Error(err.Error())
	return err
}

// getLastIndex is an easy accessor to handle getting a Consul index value
// from a sync.Map.
// We know we only stored uint64 values, so we cast the returned value as uint64.
func getLastIndex(key string) uint64 {
	inferaceVal, ok := lastIndexes.Load(key)
	if !ok {
		return 0
	}
	return inferaceVal.(uint64)
}

// storeLastIndex is an easy accessor to handle storing a Consul index value
// in a sync.Map.
// For even more ease, we return the value we just stored.
func storeLastIndex(key string, value interface{}) uint64 {
	lastIndexes.Store(key, value)
	return value.(uint64)
}

// parseConsulService parses the entries returned by the Consul request to determine:
// - the available upstreams
// - the options specified as tags on the Consul service
// All the options extracted from the Consul tags are parsed via the `reflect` package
// and handled as tags on the struct.
// Handled cases:
// - a struct tag like this: caddy:"enable-auth" corresponds to a tag matching
//   `caddy:enable-auth` in Consul
// A struct tag like this: caddy:"name=(.*)" corresponds to a tag matching
// `caddy:name=test` and will store "test" in the options returned
func parseConsulService(entries []*api.ServiceEntry) (upstreams []*reverseproxy.Upstream, options *SubdomainReverseProxyOptions) {

	options = &SubdomainReverseProxyOptions{}
	upstreams = make([]*reverseproxy.Upstream, 0, len(entries))

	t := reflect.TypeOf(*options)
	v := reflect.ValueOf(options).Elem()

	for _, entry := range entries {

		// We add the instance as an upstream
		upstreams = append(upstreams, &reverseproxy.Upstream{
			Dial: fmt.Sprintf("%s:%d", entry.Service.Address, entry.Service.Port),
		})

		// We check the options on that instance
		for i := 0; i < t.NumField(); i++ {

			field := t.Field(i)
			optionTag := field.Tag.Get("caddy")

			for _, tag := range entry.Service.Tags {

				regex, err := regexp.Compile(fmt.Sprintf("caddy:%s", optionTag))
				if err != nil {
					continue
				}

				match := regex.FindStringSubmatch(tag)
				if len(match) > 0 {

					fieldValue := v.FieldByName(field.Name)

					switch fieldValue.Kind() {
					case reflect.Bool:
						fieldValue.SetBool(true)
					case reflect.String:
						fieldValue.SetString(match[1])
					case reflect.Int:
						val, err := strconv.ParseInt(match[1], 10, 0)
						if err != nil {
							continue
						}
						fieldValue.SetInt(val)
					}
				}

			}

		}
	}

	return
}
