package node_stats

import "github.com/elastic/beats/v7/metricbeat/module/aerospike"

type NodeStatsConfig struct {
	Whitelist []string `config:"node_stats.whitelist"`
	Blacklist []string `config:"node_stats.blacklist"`
	aerospike.Config
}

func DefaultNodeStatsConfig() NodeStatsConfig {
	return NodeStatsConfig{
		Whitelist: []string{},
		Blacklist: []string{},
		Config:    aerospike.DefaultConfig(),
	}
}
