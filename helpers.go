package caddyconsul

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/hashicorp/consul/api"
)

func asJSON(obj interface{}) (sliceArray []byte) {
	sliceArray, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		caddy.Log().Error(fmt.Sprintf("Error while converting object to JSON: %s", err))
	}
	return
}

func getLastIndex(key string) uint64 {
	inferaceVal, ok := lastIndexes.Load(key)
	if !ok {
		return 0
	}
	return inferaceVal.(uint64)
}

func storeLastIndex(key string, value interface{}) uint64 {
	lastIndexes.Store(key, value)
	return value.(uint64)
}

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
