// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The ctdns_server binary runs the CT personality for DNS.
package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/etcd/clientv3"
	etcdnaming "github.com/coreos/etcd/clientv3/naming"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/naming"

	// Register PEMKeyFile, PrivateKey and PKCS11Config ProtoHandlers
	_ "github.com/google/trillian/crypto/keys/der/proto"
	_ "github.com/google/trillian/crypto/keys/pem/proto"
	_ "github.com/google/trillian/crypto/keys/pkcs11/proto"
)

// Global flags that affect all log instances.
var (
	metricsEndpoint    = flag.String("metrics_endpoint", "localhost:8053", "Endpoint for serving metrics; if left empty, metrics will be visible on --http_endpoint")
	rpcBackend         = flag.String("log_rpc_server", "localhost:8090", "Backend specification; comma-separated list or etcd service name (if --etcd_servers specified). If unset backends are specified in config (as a LogMultiConfig proto)")
	rpcDeadline        = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
	getSTHInterval     = flag.Duration("get_sth_interval", time.Second*180, "Interval between internal get-sth operations (0 to disable)")
	logConfig          = flag.String("log_config", "", "File holding log config in text proto format")
	etcdServers        = flag.String("etcd_servers", "", "A comma-separated list of etcd servers")
	etcdMetricsService = flag.String("etcd_metrics_service", "trillian-ctdns-metrics-http", "Service name to announce our HTTP metrics endpoint under")
	startupWait        = flag.Duration("startup_wait", time.Second*5, "How long to wait for UDP server startup")
)

func main() {
	// TODO(Martin2112): Share some of the code in this file with CTFE not copy.
	flag.Parse()
	ctx := context.Background()

	cfg, beMap := ctfe.MustLoadCTFEConfig(*rpcBackend, *logConfig)

	glog.CopyStandardLogTo("WARNING")
	glog.Info("**** CT DNS Server Starting ****")

	var res naming.Resolver
	var err error
	if len(*etcdServers) > 0 {
		// Use etcd to provide endpoint resolution.
		cfg := clientv3.Config{Endpoints: strings.Split(*etcdServers, ","), DialTimeout: 5 * time.Second}
		client, err := clientv3.New(cfg)
		if err != nil {
			glog.Exitf("Failed to connect to etcd at %v: %v", *etcdServers, err)
		}
		etcdRes := &etcdnaming.GRPCResolver{Client: client}
		res = etcdRes

		// Also announce ourselves.
		updateMetrics := naming.Update{Op: naming.Add, Addr: *metricsEndpoint}
		glog.Infof("Announcing our presence in %v with %+v", *etcdMetricsService, updateMetrics)
		etcdRes.Update(ctx, *etcdMetricsService, updateMetrics)

		byeMetrics := naming.Update{Op: naming.Delete, Addr: *metricsEndpoint}
		defer func() {
			glog.Infof("Removing our presence in %v with %+v", *etcdMetricsService, byeMetrics)
			etcdRes.Update(ctx, *etcdMetricsService, byeMetrics)
		}()
	} else {
		// Use a DNS naming resolver.
		res, err = naming.NewDNSResolverWithFreq(time.Second)
		if err != nil {
			glog.Exitf("Could not create naming resolver: %v", err)
		}
	}

	// Dial all our log backends.
	clientMap := make(map[string]trillian.TrillianLogClient)
	for _, be := range beMap {
		glog.Infof("Dialling backend: %v", be)
		bal := grpc.RoundRobin(res)
		opts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBalancer(bal)}
		if len(beMap) == 1 {
			// If there's only one of them we use the blocking option as we can't
			// serve anything until connected.
			opts = append(opts, grpc.WithBlock())
		}
		conn, err := grpc.Dial(be.BackendSpec, opts...)
		if err != nil {
			glog.Exitf("Could not dial RPC udpServer: %v: %v", be, err)
		}
		defer conn.Close()
		clientMap[be.Name] = trillian.NewTrillianLogClient(conn)
	}

	// Register DNS handlers for all the configured logs using the correct RPC
	// client. Ignore any that don't specify a zone.
	var zones int
	for _, c := range cfg.LogConfigs.Config {
		if len(c.DnsZone) > 0 {
			zones++
			if err := setupDNSHandler(clientMap[c.LogBackendName], *rpcDeadline, c); err != nil {
				glog.Exitf("Failed to set up DNS log instance for %+v: %v", cfg, err)
			}
		}
	}

	if zones == 0 {
		glog.Exitf("No logs have a dns_zone configured. Exiting.")
	}

	// Handle metrics on the DefaultServeMux. We don't serve HTTP requests
	// for clients, only DNS.
	http.Handle("/metrics", promhttp.Handler())

	// Return a 200 on the root, for GCE default health checking :/
	http.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) { resp.WriteHeader(http.StatusOK) })

	if *getSTHInterval > 0 {
		// Regularly update the internal STH for each log so our metrics stay up-to-date with any tree head
		// changes.
		for _, c := range cfg.LogConfigs.Config {
			ticker := time.NewTicker(*getSTHInterval)
			go func(c *configpb.LogConfig) {
				glog.Infof("start internal get-sth operations on log %v (%d)", c.Prefix, c.LogId)
				for t := range ticker.C {
					glog.V(1).Infof("tick at %v: force internal get-sth for log %v (%d)", t, c.Prefix, c.LogId)
					if _, err := ctfe.GetTreeHead(ctx, clientMap[c.LogBackendName], c.LogId, c.Prefix); err != nil {
						glog.Warningf("failed to retrieve tree head for log %v (%d): %v", c.Prefix, c.LogId, err)
					}
				}
			}(c)
		}
	}

	// Bring up the DNS udpServer and serve until we get a signal not to.
	go awaitSignal(func() {
		os.Exit(1)
	})
	// TODO(Martin2112): Might need a separate metrics endpoint like CTFE.
	// Bring up the UDP Server and allow time for it to start.
	ch := make(chan bool)
	udpServer := dns.Server{
		Addr:       *metricsEndpoint,
		Net:        "udp",
		TsigSecret: nil,
		NotifyStartedFunc: func() {
			ch <- true
		},
	}

	// Allow a short time for the UDP server to notify us that it is ready.
	go udpServer.ListenAndServe()
	select {
	case res := <-ch:
		glog.Infof("UDP Server has started OK: %v", res)
	case <-time.After(*startupWait):
		glog.Exitf("UDP Server not listening within timeout")
	}

	// Now start the TCP server.
	tcpServer := dns.Server{
		Addr:       *metricsEndpoint,
		Net:        "tcp",
		TsigSecret: nil}
	if err := tcpServer.ListenAndServe(); err != nil {
		glog.Errorf("Failed to setup the TCP DNS Server: %s\n", err.Error())
	}
	glog.Flush()
}

// awaitSignal waits for standard termination signals, then runs the given
// function; it should be run as a separate goroutine.
func awaitSignal(doneFn func()) {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block main and wait for a signal
	sig := <-sigs
	glog.Warningf("Signal received: %v", sig)
	glog.Flush()

	doneFn()
}

func setupDNSHandler(client trillian.TrillianLogClient, deadline time.Duration, cfg *configpb.LogConfig) error {
	opts := ctfe.InstanceOptions{
		Deadline:      deadline,
		MetricFactory: prometheus.MetricFactory{},
		RequestLog:    new(ctfe.DefaultRequestLog),
	}
	logCtx, err := ctfe.SetUpDNSInstance(context.Background(), client, cfg, opts)
	if err != nil {
		return err
	}
	handler := ctfe.NewDNS(cfg, logCtx)
	dns.DefaultServeMux.Handle(cfg.DnsZone, handler)
	return nil
}

