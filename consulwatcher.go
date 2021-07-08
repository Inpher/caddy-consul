package caddyconsul

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/hashicorp/consul/api"
)

// watchConsul starts all the Consul requesting go-routines,
// handles the initDone flag and handles the events triggered
// by the requests to Consul
func (cc *App) watchConsul() {

	// Two chanels supporting the config and services transmissions
	configChan := make(chan *caddy.Config)
	servicesChan := make(chan serviceEntries)

	// A local channel used to notify and propagate that init is done
	localInitDoneChan := make(chan bool)

	// Three channels are used to shutdown the different goroutines in the app
	stopChan := make(chan bool)
	shutdownKV := make(chan bool)
	shutdownServices := make(chan bool)

	// Two wait groups to ensure that init is indeed done
	var confInitWaitGroup sync.WaitGroup
	var servicesInitWaitGroup sync.WaitGroup

	// And two wait groups to ensure that shutdown is done
	var confWaitGroup sync.WaitGroup
	var servicesWaitGroup sync.WaitGroup

	// Global lock mutex to avoid updating the config and services during the generation of the Caddy JSON config
	var lock sync.Mutex

	// We will at least wait for the first config
	// and the first call to load all available services
	confInitWaitGroup.Add(1)
	servicesInitWaitGroup.Add(1)
	confWaitGroup.Add(1)
	servicesWaitGroup.Add(1)

	// Starting to watch Consul
	go cc.watchConsulKV(configChan, shutdownKV, &confInitWaitGroup, &confWaitGroup)
	go cc.watchConsulServices(servicesChan, shutdownServices, &servicesInitWaitGroup, &servicesWaitGroup)

	initDone := globalInitDone

	// Wait for init and wait for shutdown
	if !initDone {
		go cc.waitForInitAndGenerateFirstConfig(&confInitWaitGroup, &servicesInitWaitGroup, localInitDoneChan)
	}
	go cc.waitForShutdownEvent(shutdownKV, shutdownServices, stopChan)

	needGeneration := false

OUTERLOOP:
	for {
		select {

		case _ = <-stopChan:
			break OUTERLOOP

		case conf := <-configChan:

			// Let's lock during the manipulation of our global vars
			lock.Lock()

			caddy.Log().Named("consul").Debug("Update to the global configuration stored in Consul detected")

			// Let's update our global config var
			globalConfig = conf

			// Caddy will shut this instance of the app and start a new one with the its new configuration when we'll call caddy.Load(),
			// though this is the current instance that will generate the next applied Caddy configuration and this generation heavily uses
			// this instance's app configuration
			// To prevent the new app configuration being used for the n+1 generation, we update it with the new one before randering
			// the next Caddy configuration JSON payload
			if conf, ok := conf.AppsRaw["consul"]; ok {
				json.Unmarshal(conf, cc)
			}

			// We will need to re-generate the configuration during next tick
			needGeneration = true

			lock.Unlock()

		case serviceEntries := <-servicesChan:

			// Let's lock during the manipulation of our global vars
			lock.Lock()

			caddy.Log().Named("consul").Debug("Update to the Consul services detected")

			// Let's update our global services var
			switch serviceEntries.EventType {
			case "update":
				globalServices[serviceEntries.Service] = serviceEntries.Entries
			case "delete":
				delete(globalServices, serviceEntries.Service)
			}

			// We will need to re-generate the configuration during next tick
			needGeneration = true

			lock.Unlock()

		case <-localInitDoneChan:

			initDone = true
			globalInitDone = true

		case <-time.After(time.Second * 2):

			// If there is no need for generation (or init has not been done yet), nothing to do
			if !needGeneration || !initDone {
				continue
			}

			var err error

			// Let's lock during our generation process
			lock.Lock()

			caddy.Log().Named("consul").Debug("Regenerating configuration")

			cc.fullConfigJSON, err = cc.generateConfAsJSON()
			if err != nil {
				caddy.Log().Error(fmt.Sprintf("Unable to generate config: %s", err))
				lock.Unlock()
				continue
			}

			// We just generated the conf, no need to do it again before the next update
			needGeneration = false

			caddy.Log().Named("consul").Debug(fmt.Sprintf("new configuration generated:\n%s\n", cc.fullConfigJSON))

			// We're not in the initial run anymore, so we have to propagate
			// the new configuration to Caddy by ourselves
			err = caddy.Load(cc.fullConfigJSON, false)
			if err != nil {
				caddy.Log().Error(fmt.Sprintf("Unable to load conf config: %s", err))
			}

			caddy.Log().Named("consul").Debug("Configuration was regenerated and applied by Caddy")

			lock.Unlock()
		}
	}

	// We wait for the config go-routine
	confWaitGroup.Wait()

	// We wait for the services go-routines
	servicesWaitGroup.Wait()

	caddy.Log().Named("consul").Info("Exiting app!")

}

// waitForInitAndGenerateFirstConfig just waits for the init waitgroups to be done
// and sends an event in the `initDone` channel
func (cc *App) waitForInitAndGenerateFirstConfig(confWaitGroup *sync.WaitGroup, servicesWaitGroup *sync.WaitGroup, initDone chan bool) {

	// We just wait for the two sync.WaitGroups to be done
	confWaitGroup.Wait()
	servicesWaitGroup.Wait()

	initDone <- true
}

// waitForShutdownEvent waits for an event received on the shutdown channel
// and broadcasts it to the config watching go-routine and the services watching
// go-routines
func (cc *App) waitForShutdownEvent(shutdownKV chan bool, shutdownServices chan bool, stopChan chan bool) {

OUTERLOOP:
	for {
		select {
		case _ = <-cc.shutdownChan:

			// Stop the Consul watching goroutines
			shutdownKV <- true
			shutdownServices <- true

			// Then stop the main goroutine
			stopChan <- true

			break OUTERLOOP
		}
	}

}

// watchConsulKV watches the Consul K/V store key holding the Caddy configuration
// this configuration is either in JSON or Caddyfile formats
func (cc *App) watchConsulKV(configChan chan *caddy.Config, shutdownKV chan bool, confInitWaitGroup *sync.WaitGroup, confWaitGroup *sync.WaitGroup) {

	stopped := false
	signalInit := true
	lastIndex := getLastIndex("consul-kv")

	KVCtx, cancelKVFunc := context.WithCancel(context.Background())

	go func() {

		<-shutdownKV

		stopped = true

		caddy.Log().Named("consul.watcher.kv").Info("Stopping KV watching routine!")

		// We shutdown the main Consul requester
		cancelKVFunc()

		// We signal the wait group that this goroutine is done
		confWaitGroup.Done()

		caddy.Log().Named("consul.watcher.kv").Debug("Stopped KV watching routine!")

	}()

	for {

		if stopped {
			caddy.Log().Named("consul.watcher.kv").Debug("Services watching routine is stopped, returning!")
			return
		}

		caddy.Log().Named("consul.watcher.kv").Debug("Requesting KV updates!")

		queryOptions := &api.QueryOptions{
			WaitIndex: lastIndex,
			WaitTime:  time.Minute * 5,
		}

		keypair, meta, err := cc.client.KV().Get(cc.ConsulGlobalConfigKey, queryOptions.WithContext(KVCtx))
		if err != nil {

			// If we canceled the context, nothing wrong here
			if KVCtx.Err() == context.Canceled {
				return
			}

			caddy.Log().Named("consul.watcher.kv").Error(fmt.Sprintf("unable to request KV value from Consul: %s", err))
			time.Sleep(time.Second * 1)
			continue
		}

		if meta == nil {
			caddy.Log().Named("consul.watcher.kv").Error("Consul returned an empty meta: key probably doesn't exist")
			time.Sleep(time.Second * 1)
			continue
		}

		if lastIndex >= meta.LastIndex {
			caddy.Log().Named("consul.watcher.kv").Debug("Consul index didn't change: this is just a request timeout")
			continue
		}

		lastIndex = storeLastIndex("consul-kv", meta.LastIndex)

		conf := &caddy.Config{}

		err = json.Unmarshal(keypair.Value, &conf)
		if err != nil {
			caddy.Log().Named("consul.watcher.kv").Debug("unable to unmarshal Consul KV content into caddy.Config struct, let's check if it's a caddyfile format")

			cfgAdapter := caddyconfig.GetAdapter("caddyfile")
			if cfgAdapter == nil {
				caddy.Log().Named("consul.watcher.kv").Error("no Caddyfile adapter found")
				continue
			}

			jsonVal, _, err := cfgAdapter.Adapt(keypair.Value, map[string]interface{}{})
			if err != nil {
				caddy.Log().Named("consul.watcher.kv").Error(fmt.Sprintf("error while adapting caddyfile to JSON: %s", err))
				continue
			}

			err = json.Unmarshal(jsonVal, &conf)
			if err != nil {
				caddy.Log().Named("consul.watcher.kv").Error("unable to unmarshal Consul KV content into caddy.Config struct")
				continue
			}
		}

		configChan <- conf

		if signalInit {
			confInitWaitGroup.Done()
			signalInit = false
		}
	}

}

// watchConsulServices watches the global services that hold the tag that we look for
// and triggers new go-routines watching the health of each returned service
func (cc *App) watchConsulServices(servicesChan chan serviceEntries, shutdownServices chan bool, servicesInitWaitGroup *sync.WaitGroup, servicesWaitGroup *sync.WaitGroup) {

	if cc.ServicesTag == "" {
		caddy.Log().Named("consul.watcher.services").Info("No services tag to watch, not watching services")
		servicesInitWaitGroup.Done()
		return
	}

	signalInit := true
	lastIndex := getLastIndex("consul-services")
	currentServices := make(map[string]func())

	stop := false
	healthCtx, cancelHealthFunc := context.WithCancel(context.Background())

	go func() {

		<-shutdownServices

		stop = true

		caddy.Log().Named("consul.watcher.services").Info("Stopping services watching routine!")

		// We shutdown the main Consul requester
		cancelHealthFunc()

		for _, cancelFunc := range currentServices {
			// We call cancelFunc to stop the goroutine that watches Consul for this service
			cancelFunc()
		}

		servicesWaitGroup.Done()

		caddy.Log().Named("consul.watcher.services").Debug("Stopped services watching routine!")

	}()

	for {

		if stop {
			caddy.Log().Named("consul.watcher.services").Debug("Services watching routine is stopped, returning!")
			return
		}

		caddy.Log().Named("consul.watcher.services").Debug("Requesting services updates!")

		options := &api.QueryOptions{
			WaitIndex: lastIndex,
			WaitTime:  time.Minute * 5,
			Filter:    fmt.Sprintf("%s in ServiceTags", cc.ServicesTag),
		}

		healthChecks, meta, err := cc.client.Health().State("passing", options.WithContext(healthCtx))
		if err != nil {

			// If we canceled the context, nothing wrong here
			if healthCtx.Err() == context.Canceled {
				return
			}

			caddy.Log().Named("consul.watcher.services").Error(fmt.Sprintf("unable to request services from Consul: %s", err))
			time.Sleep(time.Second * 1)
			continue
		}

		if meta == nil {
			caddy.Log().Named("consul.watcher.services").Error("Consul returned an empty meta...?")
			time.Sleep(time.Second * 1)
			continue
		}

		if lastIndex >= meta.LastIndex {
			caddy.Log().Named("consul.watcher.services").Debug("Consul index didn't change: this is just a request timeout")
			continue
		}

		lastIndex = storeLastIndex("consul-services", meta.LastIndex)

		caddy.Log().Named("consul.watcher.services").Debug("Services list updated")

		services := make(map[string]bool)
		for _, service := range healthChecks {
			services[service.ServiceName] = true
		}

		// Let's start by iterating on the services we have to monitor
		for serviceName := range services {

			if _, ok := currentServices[serviceName]; !ok {

				// Create a new context that can be canceled if the service is not to be monitored anymore
				ctx, cancelFunc := context.WithCancel(context.Background())

				// Fill our services map with the cancel function for when we'll be needing it
				currentServices[serviceName] = cancelFunc

				// Launch the dedicated goroutine
				go cc.watchConsulServiceHealthyEntries(ctx, serviceName, servicesChan, servicesInitWaitGroup, signalInit)

			}

		}

		if signalInit {
			caddy.Log().Named("consul.watcher.services").Debug(fmt.Sprintf("adding %d to the services sync.WaitGroup for the initialization", len(services)))
			servicesInitWaitGroup.Add(len(services))
			servicesInitWaitGroup.Done()
			signalInit = false
		}

		// And now, let's clean the services that we don't need to monitor anymore
		for serviceName, cancelFunc := range currentServices {
			if _, ok := services[serviceName]; !ok {

				// We call cancelFunc to stop the goroutine that watches Consul for this service
				cancelFunc()

				// We remove the service from our current watched services
				delete(currentServices, serviceName)

				// We send the delete event to the main watcher for propagation
				servicesChan <- serviceEntries{
					EventType: "delete",
					Service:   serviceName,
				}
			}
		}

	}

}

// watchConsulServiceHealthyEntries watches the health of a specific service
func (cc *App) watchConsulServiceHealthyEntries(ctx context.Context, serviceName string, servicesChan chan serviceEntries, servicesInitWaitGroup *sync.WaitGroup, signalInit bool) {

	lastIndex := getLastIndex(fmt.Sprintf("consul-services-%s", serviceName))

	for {

		select {
		case <-ctx.Done():
			caddy.Log().Named(fmt.Sprintf("consul.watcher.services.health.%s", serviceName)).Info("Closing service watcher")
			return

		default:

			queryOptions := &api.QueryOptions{
				WaitIndex: lastIndex,
				WaitTime:  time.Minute * 5,
			}

			consulServiceEntries, meta, err := cc.client.Health().Service(serviceName, cc.ServicesTag, true, queryOptions.WithContext(ctx))
			if err != nil {

				// If we canceled the context, nothing wrong here
				if ctx.Err() == context.Canceled {
					return
				}

				caddy.Log().Named(fmt.Sprintf("consul.watcher.services.health.%s", serviceName)).Error(fmt.Sprintf("unable to request healthy service entries from Consul: %s", err))
				time.Sleep(time.Second * 1)
				continue
			}

			if meta == nil {
				caddy.Log().Named(fmt.Sprintf("consul.watcher.services.health.%s", serviceName)).Error("Consul returned an empty meta... service doesn't exist anymore?")
				time.Sleep(time.Second * 1)
				continue
			}

			if lastIndex >= meta.LastIndex {
				caddy.Log().Named(fmt.Sprintf("consul.watcher.services.health.%s", serviceName)).Debug("Consul index didn't change: this is just a request timeout")
				continue
			}

			caddy.Log().Named(fmt.Sprintf("consul.watcher.services.health.%s", serviceName)).Debug("Service health updated")

			lastIndex = storeLastIndex(fmt.Sprintf("consul-services-%s", serviceName), meta.LastIndex)

			servicesChan <- serviceEntries{
				EventType: "update",
				Service:   serviceName,
				Entries:   consulServiceEntries,
			}

			if signalInit {
				servicesInitWaitGroup.Done()
				signalInit = false
			}

		}

	}

}
