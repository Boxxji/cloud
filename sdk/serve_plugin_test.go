// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cloud

func testListenCfg() *Config {
	return &Config{ListenAddr: ":8080", ZAPListenAddr: ":9653", HealthListenAddr: ":9090"}
}
