package observability

import "expvar"

var (
	DecisionsTotal  = expvar.NewInt("pdp_decisions_total")
	DecisionsAllow  = expvar.NewInt("pdp_decisions_allow")
	DecisionsDeny   = expvar.NewInt("pdp_decisions_deny")
	DecisionsStepUp = expvar.NewInt("pdp_decisions_step_up")
	CacheHits       = expvar.NewInt("pdp_decision_cache_hits")
	CacheMisses     = expvar.NewInt("pdp_decision_cache_misses")
	LatencyBuckets  = expvar.NewMap("pdp_decision_latency_ms")
)

// RecordLatency increments an expvar bucket for decision latency.
// Buckets: 5,10,25,50,100,250,500,1000,inf (ms).
func RecordLatency(action string, ms int64) {
	switch {
	case ms <= 5:
		incrementBucket("le_5")
	case ms <= 10:
		incrementBucket("le_10")
	case ms <= 25:
		incrementBucket("le_25")
	case ms <= 50:
		incrementBucket("le_50")
	case ms <= 100:
		incrementBucket("le_100")
	case ms <= 250:
		incrementBucket("le_250")
	case ms <= 500:
		incrementBucket("le_500")
	case ms <= 1000:
		incrementBucket("le_1000")
	default:
		incrementBucket("gt_1000")
	}
	if action != "" {
		LatencyBuckets.Add("action."+actionKey(action), 1)
	}
}

func incrementBucket(name string) {
	cur := LatencyBuckets.Get(name)
	if cur == nil {
		LatencyBuckets.Set(name, new(expvar.Int))
		cur = LatencyBuckets.Get(name)
	}
	cur.(*expvar.Int).Add(1)
}

func actionKey(action string) string {
	const max = 40
	if len(action) > max {
		return action[:max]
	}
	return action
}
