package node_stats

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common/schema"

	s "github.com/elastic/beats/v7/libbeat/common/schema"
	c "github.com/elastic/beats/v7/libbeat/common/schema/mapstrstr"
)

var nodeStatsSchema = s.Schema{
	"batch_index_complete":                  c.Int("batch_index_complete"),
	"batch_index_created_buffers":           c.Int("batch_index_created_buffers"),
	"batch_index_delay":                     c.Int("batch_index_delay"),
	"batch_index_destroyed_buffers":         c.Int("batch_index_destroyed_buffers"),
	"batch_index_error":                     c.Int("batch_index_error"),
	"batch_index_huge_buffers":              c.Int("batch_index_huge_buffers"),
	"batch_index_initiate":                  c.Int("batch_index_initiate"),
	"batch_index_proto_compression_ratio":   c.Float("batch_index_proto_compression_ratio"),
	"batch_index_proto_uncompressed_pct":    c.Float("batch_index_proto_uncompressed_pct"),
	"batch_index_queue":                     convertBatchIndexQueue("batch_index_queue"), // example: "0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0",
	"batch_index_timeout":                   c.Int("batch_index_timeout"),
	"batch_index_unused_buffers":            c.Int("batch_index_unused_buffers"),
	"client_connections":                    c.Int("client_connections"),
	"client_connections_closed":             c.Int("client_connections_closed"),
	"client_connections_opened":             c.Int("client_connections_opened"),
	"cluster_clock_skew_ms":                 c.Int("cluster_clock_skew_ms"),
	"cluster_clock_skew_outliers":           c.Str("cluster_clock_skew_outliers"),
	"cluster_clock_skew_stop_writes_sec":    c.Int("cluster_clock_skew_stop_writes_sec"),
	"cluster_duplicate_nodes":               c.Str("cluster_duplicate_nodes"),
	"cluster_generation":                    c.Int("cluster_generation"),
	"cluster_integrity":                     c.Bool("cluster_integrity"),
	"cluster_is_member":                     c.Bool("cluster_is_member"),
	"cluster_key":                           c.Str("cluster_key"), // Randomly generated 64 bit hexadecimal string used to name the last Paxos cluster state agreement.
	"cluster_max_compatibility_id":          c.Int("cluster_max_compatibility_id"),
	"cluster_min_compatibility_id":          c.Int("cluster_min_compatibility_id"),
	"cluster_principal":                     c.Str("cluster_principal"),
	"cluster_size":                          c.Int("cluster_size"),
	"demarshal_error":                       c.Int("demarshal_error"),
	"early_tsvc_client_error":               c.Int("early_tsvc_client_error"), // Removed in 7.2.0
	"early_tsvc_from_proxy_batch_sub_error": c.Int("early_tsvc_from_proxy_batch_sub_error"),
	"early_tsvc_from_proxy_error":           c.Int("early_tsvc_from_proxy_error"),
	"fabric_bulk_recv_rate":                 c.Int("fabric_bulk_recv_rate"),
	"fabric_bulk_send_rate":                 c.Int("fabric_bulk_send_rate"),
	"fabric_connections":                    c.Int("fabric_connections"),
	"fabric_connections_closed":             c.Int("fabric_connections_closed"),
	"fabric_connections_opened":             c.Int("fabric_connections_opened"),
	"fabric_ctrl_recv_rate":                 c.Int("fabric_ctrl_recv_rate"),
	"fabric_ctrl_send_rate":                 c.Int("fabric_ctrl_send_rate"),
	"fabric_meta_recv_rate":                 c.Int("fabric_meta_recv_rate"),
	"fabric_meta_send_rate":                 c.Int("fabric_meta_send_rate"),
	"fabric_rw_recv_rate":                   c.Int("fabric_rw_recv_rate"),
	"fabric_rw_send_rate":                   c.Int("fabric_rw_send_rate"),
	"failed_best_practices":                 c.Bool("failed_best_practices"),
	"heap_active_kbytes":                    c.Int("heap_active_kbytes"),
	"heap_allocated_kbytes":                 c.Int("heap_allocated_kbytes"),
	"heap_efficiency_pct":                   c.Int("heap_efficiency_pct"),
	"heap_mapped_kbytes":                    c.Int("heap_mapped_kbytes"),
	"heap_site_count":                       c.Int("heap_site_count"),
	"heartbeat_connections":                 c.Int("heartbeat_connections"),
	"heartbeat_connections_closed":          c.Int("heartbeat_connections_closed"),
	"heartbeat_connections_opened":          c.Int("heartbeat_connections_opened"),
	"heartbeat_received_foreign":            c.Int("heartbeat_received_foreign"),
	"heartbeat_received_self":               c.Int("heartbeat_received_self"),
	"info_complete":                         c.Int("info_complete"),
	"info_queue":                            c.Int("info_queue"),
	"info_timeout":                          c.Int("info_timeout"),
	"long_queries_active":                   c.Int("long_queries_active"),
	"migrate_allowed":                       c.Bool("migrate_allowed"),
	"migrate_partitions_remaining":          c.Int("migrate_partitions_remaining"),
	"objects":                               c.Int("objects"),
	"paxos_principal":                       c.Str("paxos_principal"),
	"process_cpu_pct":                       c.Int("process_cpu_pct"),
	"proxy_in_progress":                     c.Int("proxy_in_progress"),
	"reaped_fds":                            c.Int("reaped_fds"),
	"rw_in_progress":                        c.Int("rw_in_progress"),
	"system_free_mem_kbytes":                c.Int("system_free_mem_kbytes"),
	"system_free_mem_pct":                   c.Int("system_free_mem_pct"),
	"system_kernel_cpu_pct":                 c.Int("system_kernel_cpu_pct"),
	"system_thp_mem_kbytes":                 c.Int("system_thp_mem_kbytes"),
	"system_total_cpu_pct":                  c.Int("system_total_cpu_pct"),
	"system_user_cpu_pct":                   c.Int("system_user_cpu_pct"),
	"threads_detached":                      c.Int("threads_detached"),
	"threads_joinable":                      c.Int("threads_joinable"),
	"threads_pool_active":                   c.Int("threads_pool_active"),
	"threads_pool_total":                    c.Int("threads_pool_total"),
	"time_since_rebalance":                  c.Int("time_since_rebalance"),
	"tombstones":                            c.Int("tombstones"),
	"tree_gc_queue":                         c.Int("tree_gc_queue"),
	"uptime":                                c.Int("uptime"),
}

func convertBatchIndexQueueInternal(queues_raw string) ([]map[string]uint64, error) {
	// example: "0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0",
	queues := strings.Split(queues_raw, ",")

	result := make([]map[string]uint64, len(queues))

	for i := range queues {
		parts := strings.Split(queues[i], ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid format for batch_index_queue at index %d: %s", i, queues[i])
		}
		request, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse requests at index %d: %w", i, err)
		}
		buffers, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse buffers at index %d: %w", i, err)
		}
		result[i] = map[string]uint64{"requests": request, "buffers": buffers}
	}
	return result, nil
}

func convertBatchIndexQueue(key string, opts ...schema.SchemaOption) schema.Conv {
	return schema.SetOptions(schema.Conv{
		Key: key,
		Func: func(key string, data map[string]interface{}) (interface{}, error) {
			rawBatchIndexQueue, ok := data[key]
			if !ok {
				return false, fmt.Errorf("missing key: %s", key)
			}

			switch batchIndexQueue := rawBatchIndexQueue.(type) {
			case string:
				return convertBatchIndexQueueInternal(batchIndexQueue)

			default:
				return false, fmt.Errorf("expected string type for key %s but got %T", key, rawBatchIndexQueue)
			}
		},
	}, opts)

}
