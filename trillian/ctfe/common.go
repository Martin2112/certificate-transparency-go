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
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/golang/glog"
)

func MustLoadCTFEConfig(backend, configPath string) (*configpb.LogMultiConfig, map[string]*configpb.LogBackend) {
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
