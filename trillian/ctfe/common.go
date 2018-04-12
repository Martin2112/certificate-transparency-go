// Copyright 2016 Google Inc. All Rights Reserved.
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

package ctfe

import (
	"context"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/naming"
)

// MustLoadConfig loads, parses and validates a CTFE / CTDNS config.
// if the config cannot be loaded or is in valid then it will exit the
// program.
func MustLoadConfig(backend, configPath string) (*configpb.LogMultiConfig, map[string]*configpb.LogBackend) {
	var cfg *configpb.LogMultiConfig
	var err error
	// Get log config from file before we start. This is a different proto
	// type if we're using a multi backend configuration (no rpcBackend set
	// in flags). The single-backend config is converted to a multi config so
	// they can be treated the same.
	if len(backend) > 0 {
		cfg, err = readCfg(configPath, backend)
	} else {
		cfg, err = readMultiCfg(configPath)
	}

	if err != nil {
		glog.Exitf("Failed to read config: %v", err)
	}

	beMap, err := ValidateLogMultiConfig(cfg)
	if err != nil {
		glog.Exitf("Invalid config: %v", err)
	}

	return cfg, beMap
}

// MustDialBackends dials one or more backends in a map. If there is only one
// RPC backend then this blocks until it has been dialled or an error occurs.
func MustDialBackends(beMap map[string]*configpb.LogBackend, res naming.Resolver) map[string]trillian.TrillianLogClient {
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
			glog.Exitf("Could not dial RPC server: %v: %v", be, err)
		}
		defer conn.Close()
		clientMap[be.Name] = trillian.NewTrillianLogClient(conn)
	}

	return clientMap
}

// StartSTHUpdates begins periodic updates of STH from the backends of logs
// specified in the config.
func StartSTHUpdates(ctx context.Context, cfg *configpb.LogMultiConfig, clientMap map[string]trillian.TrillianLogClient, interval time.Duration) {
	// Regularly update the internal STH for each log so our metrics stay up-to-date with any tree head
	// changes that are not triggered by us.
	for _, c := range cfg.LogConfigs.Config {
		ticker := time.NewTicker(interval)
		go func(c *configpb.LogConfig) {
			glog.Infof("start internal get-sth operations on log %v (%d)", c.Prefix, c.LogId)
			for t := range ticker.C {
				glog.V(1).Infof("tick at %v: force internal get-sth for log %v (%d)", t, c.Prefix, c.LogId)
				if _, err := GetTreeHead(ctx, clientMap[c.LogBackendName], c.LogId, c.Prefix); err != nil {
					glog.Warningf("failed to retrieve tree head for log %v (%d): %v", c.Prefix, c.LogId, err)
				}
			}
		}(c)
	}
}

func readMultiCfg(filename string) (*configpb.LogMultiConfig, error) {
	cfg, err := MultiLogConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func readCfg(filename string, backendSpec string) (*configpb.LogMultiConfig, error) {
	cfg, err := LogConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	return ToMultiLogConfig(cfg, backendSpec), nil
}
