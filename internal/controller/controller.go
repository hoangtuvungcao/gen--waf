package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"genwaf/internal/config"
	"genwaf/internal/policy"
)

type Snapshot struct {
	CurrentMode string                 `json:"current_mode"`
	Reason      string                 `json:"reason"`
	LastUpdated time.Time              `json:"last_updated"`
	Effective   policy.EffectiveConfig `json:"effective"`
}

type ConfigVersion struct {
	Version   int                    `json:"version"`
	CreatedAt time.Time              `json:"created_at"`
	Source    string                 `json:"source"`
	Mode      string                 `json:"mode"`
	Reason    string                 `json:"reason"`
	Effective policy.EffectiveConfig `json:"effective"`
}

type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	Mode      string    `json:"mode"`
}

type NodeRegistration struct {
	NodeID            string    `json:"node_id"`
	Address           string    `json:"address"`
	Role              string    `json:"role"`
	Version           string    `json:"version"`
	Capabilities      []string  `json:"capabilities"`
	RegisteredAt      time.Time `json:"registered_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	LastAckVersion    int       `json:"last_ack_version"`
	LastAckMode       string    `json:"last_ack_mode"`
	LastDecisionSync  time.Time `json:"last_decision_sync"`
	LastEffectiveSync time.Time `json:"last_effective_sync"`
}

type SharedDecision struct {
	ID            string    `json:"id"`
	ClientIP      string    `json:"client_ip"`
	FingerprintID string    `json:"fingerprint_id,omitempty"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	Source        string    `json:"source"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type DecisionInput struct {
	ClientIP   string `json:"client_ip"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	Source     string `json:"source"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type NodeHeartbeat struct {
	NodeID            string `json:"node_id"`
	Address           string `json:"address"`
	Role              string `json:"role"`
	Version           string `json:"version"`
	LastAckVersion    int    `json:"last_ack_version"`
	LastAckMode       string `json:"last_ack_mode"`
	DecisionSyncCount int    `json:"decision_sync_count"`
}

type ClusterBundle struct {
	GeneratedAt        time.Time              `json:"generated_at"`
	CurrentVersion     ConfigVersion          `json:"current_version"`
	Effective          policy.EffectiveConfig `json:"effective"`
	SharedDecisions    []SharedDecision       `json:"shared_decisions"`
	SharedObservations []ObservationAggregate `json:"shared_observations"`
}

type ClientObservation struct {
	NodeID               string `json:"node_id"`
	ClientIP             string `json:"client_ip"`
	FingerprintID        string `json:"fingerprint_id,omitempty"`
	TLSFingerprint       string `json:"tls_fingerprint,omitempty"`
	TLSFingerprintSource string `json:"tls_fingerprint_source,omitempty"`
	EdgeBotScore         int    `json:"edge_bot_score,omitempty"`
	HTTPFingerprint      string `json:"http_fingerprint,omitempty"`
	Requests             int    `json:"requests"`
	ChallengeFailures    int    `json:"challenge_failures"`
	SensitiveHits        int    `json:"sensitive_hits"`
	WindowSeconds        int    `json:"window_seconds"`
}

type ObservationBatch struct {
	NodeID        string              `json:"node_id"`
	GeneratedAt   time.Time           `json:"generated_at"`
	WindowSeconds int                 `json:"window_seconds"`
	Observations  []ClientObservation `json:"observations"`
}

type ObservationAggregate struct {
	ClientIP             string    `json:"client_ip"`
	FingerprintID        string    `json:"fingerprint_id,omitempty"`
	TLSFingerprint       string    `json:"tls_fingerprint,omitempty"`
	TLSFingerprintSource string    `json:"tls_fingerprint_source,omitempty"`
	EdgeBotScore         int       `json:"edge_bot_score,omitempty"`
	HTTPFingerprint      string    `json:"http_fingerprint,omitempty"`
	Requests             int       `json:"requests"`
	ChallengeFailures    int       `json:"challenge_failures"`
	SensitiveHits        int       `json:"sensitive_hits"`
	ReputationScore      int       `json:"reputation_score"`
	LastNodeID           string    `json:"last_node_id"`
	UpdatedAt            time.Time `json:"updated_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type FingerprintObservationAggregate struct {
	FingerprintID        string    `json:"fingerprint_id"`
	TLSFingerprint       string    `json:"tls_fingerprint,omitempty"`
	TLSFingerprintSource string    `json:"tls_fingerprint_source,omitempty"`
	EdgeBotScore         int       `json:"edge_bot_score,omitempty"`
	HTTPFingerprint      string    `json:"http_fingerprint,omitempty"`
	Requests             int       `json:"requests"`
	ChallengeFailures    int       `json:"challenge_failures"`
	SensitiveHits        int       `json:"sensitive_hits"`
	ReputationScore      int       `json:"reputation_score"`
	DistinctIPs          int       `json:"distinct_ips"`
	LastNodeID           string    `json:"last_node_id"`
	UpdatedAt            time.Time `json:"updated_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type persistedState struct {
	CurrentMode string                      `json:"current_mode"`
	Reason      string                      `json:"reason"`
	LastUpdated time.Time                   `json:"last_updated"`
	Audit       []AuditEvent                `json:"audit"`
	Nodes       map[string]NodeRegistration `json:"nodes"`
	Versions    []ConfigVersion             `json:"versions"`
	Decisions   map[string]SharedDecision   `json:"decisions"`
}

type Controller struct {
	mu                 sync.RWMutex
	cfg                config.Config
	currentMode        string
	reason             string
	lastUpdated        time.Time
	audit              []AuditEvent
	nodes              map[string]NodeRegistration
	versions           []ConfigVersion
	decisions          map[string]SharedDecision
	observations       map[string]ObservationAggregate
	fingerprints       map[string]FingerprintObservationAggregate
	fingerprintClients map[string]map[string]time.Time
	redisStore         *RedisStore
	statePath          string
}

func New(cfg config.Config) *Controller {
	c := &Controller{
		cfg:                cfg,
		currentMode:        cfg.System.Mode,
		reason:             "bootstrapped from config",
		lastUpdated:        time.Now().UTC(),
		nodes:              make(map[string]NodeRegistration),
		decisions:          make(map[string]SharedDecision),
		observations:       make(map[string]ObservationAggregate),
		fingerprints:       make(map[string]FingerprintObservationAggregate),
		fingerprintClients: make(map[string]map[string]time.Time),
		statePath:          cfg.Cluster.ControllerStatePath,
	}
	if store, err := newRedisStore(cfg.Storage); err == nil {
		c.redisStore = store
	} else {
		c.appendAudit("redis_init_failed", err.Error())
	}
	if c.loadState() {
		c.pruneExpiredDecisionsLocked()
		c.appendAudit("restore", "restored controller state from disk")
		_ = c.persistLocked()
		return c
	}
	c.appendAudit("bootstrap", c.reason)
	c.recordVersion("bootstrap", c.reason)
	_ = c.persistLocked()
	return c
}

func (c *Controller) Status() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Snapshot{
		CurrentMode: c.currentMode,
		Reason:      c.reason,
		LastUpdated: c.lastUpdated,
		Effective:   policy.Compile(c.cfg, c.currentMode),
	}
}

func (c *Controller) Evaluate(metrics policy.ObservedMetrics) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	prevMode := c.currentMode
	nextMode, reasons := policy.DecideNextMode(c.cfg, c.currentMode, metrics)
	c.currentMode = nextMode
	c.reason = joinReasons(reasons)
	c.lastUpdated = time.Now().UTC()
	if prevMode != nextMode {
		c.appendAudit("mode_transition", fmt.Sprintf("mode changed from %s to %s: %s", prevMode, nextMode, c.reason))
		c.recordVersion("metrics_eval", c.reason)
	} else {
		c.appendAudit("metrics_eval", c.reason)
	}
	_ = c.persistLocked()

	return Snapshot{
		CurrentMode: c.currentMode,
		Reason:      c.reason,
		LastUpdated: c.lastUpdated,
		Effective:   policy.Compile(c.cfg, c.currentMode),
	}
}

func (c *Controller) SetMode(mode, reason string) (Snapshot, error) {
	if mode == "" {
		return Snapshot{}, fmt.Errorf("mode must not be empty")
	}
	switch mode {
	case config.ModeNormal, config.ModeElevated, config.ModeUnderAttack, config.ModeMaintenance:
	default:
		return Snapshot{}, fmt.Errorf("unsupported mode %q", mode)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentMode = mode
	if reason == "" {
		reason = "manual override"
	}
	c.reason = reason
	c.lastUpdated = time.Now().UTC()
	c.appendAudit("manual_mode_override", reason)
	c.recordVersion("manual_override", reason)
	_ = c.persistLocked()

	return Snapshot{
		CurrentMode: c.currentMode,
		Reason:      c.reason,
		LastUpdated: c.lastUpdated,
		Effective:   policy.Compile(c.cfg, c.currentMode),
	}, nil
}

func (c *Controller) CurrentVersion() ConfigVersion {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.versions) == 0 {
		return ConfigVersion{}
	}
	return c.versions[len(c.versions)-1]
}

func (c *Controller) Versions() []ConfigVersion {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]ConfigVersion, len(c.versions))
	copy(out, c.versions)
	return out
}

func (c *Controller) Simulate(metrics policy.ObservedMetrics) Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nextMode, reasons := policy.DecideNextMode(c.cfg, c.currentMode, metrics)
	return Snapshot{
		CurrentMode: nextMode,
		Reason:      joinReasons(reasons),
		LastUpdated: time.Now().UTC(),
		Effective:   policy.Compile(c.cfg, nextMode),
	}
}

func (c *Controller) AuditTrail() []AuditEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]AuditEvent, len(c.audit))
	copy(out, c.audit)
	return out
}

func (c *Controller) RegisterNode(node NodeRegistration) NodeRegistration {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	node.RegisteredAt = now
	node.LastSeenAt = now
	c.nodes[node.NodeID] = node
	c.appendAudit("node_registration", fmt.Sprintf("registered node %s at %s", node.NodeID, node.Address))
	_ = c.persistLocked()
	return node
}

func (c *Controller) HeartbeatNode(hb NodeHeartbeat) (NodeRegistration, error) {
	if hb.NodeID == "" {
		return NodeRegistration{}, fmt.Errorf("node_id must not be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	node, ok := c.nodes[hb.NodeID]
	if !ok {
		node = NodeRegistration{
			NodeID:       hb.NodeID,
			Address:      hb.Address,
			Role:         hb.Role,
			Version:      hb.Version,
			RegisteredAt: time.Now().UTC(),
		}
	}
	node.Address = hb.Address
	node.Role = hb.Role
	node.Version = hb.Version
	node.LastSeenAt = time.Now().UTC()
	node.LastAckVersion = hb.LastAckVersion
	node.LastAckMode = hb.LastAckMode
	if hb.DecisionSyncCount > 0 {
		node.LastDecisionSync = node.LastSeenAt
	}
	if hb.LastAckVersion > 0 {
		node.LastEffectiveSync = node.LastSeenAt
	}
	c.nodes[hb.NodeID] = node
	c.appendAudit("node_heartbeat", fmt.Sprintf("heartbeat from %s ack_version=%d mode=%s", hb.NodeID, hb.LastAckVersion, hb.LastAckMode))
	_ = c.persistLocked()
	return node, nil
}

func (c *Controller) Nodes() []NodeRegistration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]NodeRegistration, 0, len(c.nodes))
	for _, node := range c.nodes {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (c *Controller) PublishDecision(in DecisionInput) (SharedDecision, error) {
	if !c.cfg.Cluster.SharedDecisions {
		return SharedDecision{}, fmt.Errorf("cluster.shared_decisions is disabled")
	}
	if in.ClientIP == "" {
		return SharedDecision{}, fmt.Errorf("client_ip must not be empty")
	}
	switch in.Action {
	case "soft_challenge", "pow_challenge", "temporary_ban", "drop_at_xdp":
	default:
		return SharedDecision{}, fmt.Errorf("unsupported action %q", in.Action)
	}

	ttl := in.TTLSeconds
	if ttl <= 0 {
		ttl = c.cfg.Cluster.SharedDecisionTTLSeconds
	}
	now := time.Now().UTC()
	decision := SharedDecision{
		ID:        decisionID(in.ClientIP, in.Action, now),
		ClientIP:  in.ClientIP,
		Action:    in.Action,
		Reason:    in.Reason,
		Source:    defaultString(in.Source, "manual"),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredDecisionsLocked()
	c.decisions[decision.ID] = decision
	c.appendAudit("shared_decision", fmt.Sprintf("published %s for %s via %s", decision.Action, decision.ClientIP, decision.Source))
	_ = c.persistLocked()
	return decision, nil
}

func (c *Controller) SharedDecisions() []SharedDecision {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredDecisionsLocked()
	out := make([]SharedDecision, 0, len(c.decisions))
	for _, decision := range c.decisions {
		out = append(out, decision)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].ClientIP
		if left == "" {
			left = "fp:" + out[i].FingerprintID
		}
		right := out[j].ClientIP
		if right == "" {
			right = "fp:" + out[j].FingerprintID
		}
		if left == right {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return left < right
	})
	return out
}

func (c *Controller) Bundle() ClusterBundle {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredDecisionsLocked()
	current := ConfigVersion{}
	if len(c.versions) > 0 {
		current = c.versions[len(c.versions)-1]
	}
	decisions := make([]SharedDecision, 0, len(c.decisions))
	for _, decision := range c.decisions {
		decisions = append(decisions, decision)
	}
	sort.Slice(decisions, func(i, j int) bool {
		left := decisions[i].ClientIP
		if left == "" {
			left = "fp:" + decisions[i].FingerprintID
		}
		right := decisions[j].ClientIP
		if right == "" {
			right = "fp:" + decisions[j].FingerprintID
		}
		if left == right {
			return decisions[i].CreatedAt.After(decisions[j].CreatedAt)
		}
		return left < right
	})
	observations := make([]ObservationAggregate, 0, len(c.observations))
	for _, entry := range c.observations {
		if entry.ExpiresAt.After(time.Now().UTC()) {
			observations = append(observations, entry)
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Requests == observations[j].Requests {
			return observations[i].ClientIP < observations[j].ClientIP
		}
		return observations[i].Requests > observations[j].Requests
	})
	if len(observations) > 256 {
		observations = observations[:256]
	}
	return ClusterBundle{
		GeneratedAt:        time.Now().UTC(),
		CurrentVersion:     current,
		Effective:          policy.Compile(c.cfg, c.currentMode),
		SharedDecisions:    decisions,
		SharedObservations: observations,
	}
}

func (c *Controller) PublishObservations(batch ObservationBatch) (map[string]any, error) {
	if !c.cfg.Cluster.SyncEnabled {
		return nil, fmt.Errorf("cluster.sync_enabled is disabled")
	}

	now := time.Now().UTC()
	window := batch.WindowSeconds
	if window <= 0 {
		window = c.cfg.Cluster.ObservationWindowSeconds
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredDecisionsLocked()
	c.pruneExpiredObservationsLocked(now)
	c.pruneExpiredFingerprintsLocked(now)

	processed := 0
	generated := 0
	for _, obs := range batch.Observations {
		if obs.ClientIP == "" || obs.Requests <= 0 {
			continue
		}
		ttl := window
		if obs.WindowSeconds > 0 {
			ttl = obs.WindowSeconds
		}
		if ttl <= 0 {
			ttl = c.cfg.Cluster.ObservationWindowSeconds
		}

		entry := c.observations[obs.ClientIP]
		entry.ClientIP = obs.ClientIP
		entry.FingerprintID = obs.FingerprintID
		entry.TLSFingerprint = obs.TLSFingerprint
		entry.TLSFingerprintSource = obs.TLSFingerprintSource
		entry.EdgeBotScore = obs.EdgeBotScore
		entry.HTTPFingerprint = obs.HTTPFingerprint
		if c.redisStore != nil {
			if redisEntry, err := c.redisStore.RecordObservation(now, batch.NodeID, obs, ttl); err == nil {
				entry = redisEntry
				entry.FingerprintID = obs.FingerprintID
				entry.TLSFingerprint = obs.TLSFingerprint
				entry.TLSFingerprintSource = obs.TLSFingerprintSource
				entry.EdgeBotScore = obs.EdgeBotScore
				entry.HTTPFingerprint = obs.HTTPFingerprint
			} else {
				entry.Requests += obs.Requests
				entry.ChallengeFailures += obs.ChallengeFailures
				entry.SensitiveHits += obs.SensitiveHits
				entry.LastNodeID = defaultString(obs.NodeID, batch.NodeID)
				entry.UpdatedAt = now
				entry.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
				c.appendAudit("redis_observation_fallback", fmt.Sprintf("fallback to local aggregation for %s: %v", obs.ClientIP, err))
			}
		} else {
			entry.Requests += obs.Requests
			entry.ChallengeFailures += obs.ChallengeFailures
			entry.SensitiveHits += obs.SensitiveHits
			entry.LastNodeID = defaultString(obs.NodeID, batch.NodeID)
			entry.UpdatedAt = now
			entry.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
		}
		c.observations[obs.ClientIP] = entry
		c.recordFingerprintObservationLocked(now, batch.NodeID, obs, ttl)
		processed++

		if decision, ok := c.decisionFromAggregateLocked(entry, now); ok {
			c.decisions[decision.ID] = decision
			generated++
		}
		if decision, ok := c.decisionFromFingerprintLocked(obs.FingerprintID, now); ok {
			c.decisions[decision.ID] = decision
			generated++
		}
	}

	if snapshot, changed := c.applyAutoModeFromObservationsLocked(now); changed {
		c.appendAudit("mode_transition", fmt.Sprintf("mode changed from cluster observations to %s: %s", snapshot.CurrentMode, snapshot.Reason))
	}

	if processed > 0 {
		c.appendAudit("cluster_observations", fmt.Sprintf("processed %d observations from node %s and generated %d shared decisions", processed, batch.NodeID, generated))
		_ = c.persistLocked()
	}

	return map[string]any{
		"processed":            processed,
		"generated_decisions":  generated,
		"tracked_clients":      len(c.observations),
		"tracked_fingerprints": len(c.fingerprints),
	}, nil
}

func (c *Controller) ObservationState() []ObservationAggregate {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpiredObservationsLocked(time.Now().UTC())
	out := make([]ObservationAggregate, 0, len(c.observations))
	for _, entry := range c.observations {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests == out[j].Requests {
			return out[i].ClientIP < out[j].ClientIP
		}
		return out[i].Requests > out[j].Requests
	})
	return out
}

func (c *Controller) FingerprintState() []FingerprintObservationAggregate {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpiredFingerprintsLocked(time.Now().UTC())
	out := make([]FingerprintObservationAggregate, 0, len(c.fingerprints))
	for _, entry := range c.fingerprints {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReputationScore == out[j].ReputationScore {
			return out[i].FingerprintID < out[j].FingerprintID
		}
		return out[i].ReputationScore > out[j].ReputationScore
	})
	return out
}

func (c *Controller) appendAudit(kind, message string) {
	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		Kind:      kind,
		Message:   message,
		Mode:      c.currentMode,
	}
	c.audit = append(c.audit, event)
	if len(c.audit) > 200 {
		c.audit = c.audit[len(c.audit)-200:]
	}
}

func (c *Controller) recordVersion(source, reason string) {
	version := ConfigVersion{
		Version:   len(c.versions) + 1,
		CreatedAt: time.Now().UTC(),
		Source:    source,
		Mode:      c.currentMode,
		Reason:    reason,
		Effective: policy.Compile(c.cfg, c.currentMode),
	}
	c.versions = append(c.versions, version)
	if len(c.versions) > 100 {
		c.versions = c.versions[len(c.versions)-100:]
	}
}

func (c *Controller) pruneExpiredDecisionsLocked() {
	now := time.Now().UTC()
	for id, decision := range c.decisions {
		if !decision.ExpiresAt.After(now) {
			delete(c.decisions, id)
		}
	}
}

func (c *Controller) pruneExpiredObservationsLocked(now time.Time) {
	for ip, entry := range c.observations {
		if !entry.ExpiresAt.After(now) {
			delete(c.observations, ip)
		}
	}
}

func (c *Controller) pruneExpiredFingerprintsLocked(now time.Time) {
	for fp, entry := range c.fingerprints {
		if !entry.ExpiresAt.After(now) {
			delete(c.fingerprints, fp)
			delete(c.fingerprintClients, fp)
			continue
		}
		applyFingerprintDecayLocked(&entry, now)
		entry.UpdatedAt = now
		clients := c.fingerprintClients[fp]
		for clientIP, expiresAt := range clients {
			if !expiresAt.After(now) {
				delete(clients, clientIP)
			}
		}
		entry.DistinctIPs = len(clients)
		c.fingerprints[fp] = entry
		if len(clients) == 0 {
			delete(c.fingerprintClients, fp)
		}
	}
}

func (c *Controller) decisionFromAggregateLocked(entry ObservationAggregate, now time.Time) (SharedDecision, bool) {
	action := ""
	reason := ""
	switch {
	case entry.ReputationScore >= 500 || entry.ChallengeFailures >= 6 || entry.Requests >= c.cfg.Cluster.SharedRateLimitThreshold*2:
		action = "temporary_ban"
		reason = "shared multi-node rate threshold or reputation threshold exceeded"
	case entry.ReputationScore >= 220 || (entry.SensitiveHits >= 1 && entry.Requests >= c.cfg.Cluster.SharedChallengeThreshold):
		action = "pow_challenge"
		reason = "shared sensitive-path pressure or reputation threshold exceeded"
	case entry.ReputationScore >= 90 || entry.Requests >= c.cfg.Cluster.SharedChallengeThreshold:
		action = "soft_challenge"
		reason = "shared request pressure or reputation threshold exceeded"
	default:
		return SharedDecision{}, false
	}

	existingStrength := c.activeDecisionStrengthForIPLocked(entry.ClientIP, now)
	nextStrength := decisionStrength(action)
	if existingStrength >= nextStrength {
		return SharedDecision{}, false
	}

	return SharedDecision{
		ID:        decisionID(entry.ClientIP, action, now),
		ClientIP:  entry.ClientIP,
		Action:    action,
		Reason:    reason,
		Source:    "cluster-observation",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(c.cfg.Cluster.SharedDecisionTTLSeconds) * time.Second),
	}, true
}

func (c *Controller) decisionFromFingerprintLocked(fingerprintID string, now time.Time) (SharedDecision, bool) {
	if fingerprintID == "" {
		return SharedDecision{}, false
	}
	entry, ok := c.fingerprints[fingerprintID]
	if !ok || !entry.ExpiresAt.After(now) {
		return SharedDecision{}, false
	}
	applyFingerprintDecayLocked(&entry, now)
	entry.UpdatedAt = now
	c.fingerprints[fingerprintID] = entry

	action := ""
	reason := ""
	switch {
	case entry.ReputationScore >= 420 || entry.ChallengeFailures >= 8 || entry.DistinctIPs >= 6:
		action = "temporary_ban"
		reason = "shared browser fingerprint reputation exceeded threshold"
	case entry.ReputationScore >= 180 || entry.ChallengeFailures >= 4 || entry.DistinctIPs >= 3:
		action = "pow_challenge"
		reason = "shared browser fingerprint looks coordinated across multiple ips"
	case entry.ReputationScore >= 80:
		action = "soft_challenge"
		reason = "shared browser fingerprint reputation is warming up"
	default:
		return SharedDecision{}, false
	}

	existingStrength := c.activeDecisionStrengthForFingerprintLocked(fingerprintID, now)
	if existingStrength >= decisionStrength(action) {
		return SharedDecision{}, false
	}

	return SharedDecision{
		ID:            decisionID("fp:"+fingerprintID, action, now),
		FingerprintID: fingerprintID,
		Action:        action,
		Reason:        reason,
		Source:        "cluster-fingerprint",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Duration(c.cfg.Cluster.SharedDecisionTTLSeconds) * time.Second),
	}, true
}

func (c *Controller) activeDecisionStrengthForIPLocked(clientIP string, now time.Time) int {
	maxStrength := 0
	for id, decision := range c.decisions {
		if decision.ClientIP != clientIP {
			continue
		}
		if !decision.ExpiresAt.After(now) {
			delete(c.decisions, id)
			continue
		}
		if strength := decisionStrength(decision.Action); strength > maxStrength {
			maxStrength = strength
		}
	}
	return maxStrength
}

func (c *Controller) activeDecisionStrengthForFingerprintLocked(fingerprintID string, now time.Time) int {
	maxStrength := 0
	for id, decision := range c.decisions {
		if decision.FingerprintID != fingerprintID {
			continue
		}
		if !decision.ExpiresAt.After(now) {
			delete(c.decisions, id)
			continue
		}
		if strength := decisionStrength(decision.Action); strength > maxStrength {
			maxStrength = strength
		}
	}
	return maxStrength
}

func (c *Controller) recordFingerprintObservationLocked(now time.Time, batchNode string, obs ClientObservation, ttl int) {
	if obs.FingerprintID == "" {
		return
	}
	entry := c.fingerprints[obs.FingerprintID]
	entry.FingerprintID = obs.FingerprintID
	entry.TLSFingerprint = obs.TLSFingerprint
	entry.TLSFingerprintSource = obs.TLSFingerprintSource
	entry.EdgeBotScore = obs.EdgeBotScore
	entry.HTTPFingerprint = obs.HTTPFingerprint
	applyFingerprintDecayLocked(&entry, now)
	entry.Requests += obs.Requests
	entry.ChallengeFailures += obs.ChallengeFailures
	entry.SensitiveHits += obs.SensitiveHits
	entry.ReputationScore += obs.Requests + obs.ChallengeFailures*12 + obs.SensitiveHits*6
	if obs.EdgeBotScore >= 80 {
		entry.ReputationScore -= 12
	} else if obs.EdgeBotScore >= 50 {
		entry.ReputationScore -= 4
	} else if obs.EdgeBotScore >= 0 && obs.EdgeBotScore <= 10 {
		entry.ReputationScore += 10
	}
	entry.LastNodeID = defaultString(obs.NodeID, batchNode)
	entry.UpdatedAt = now
	entry.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
	entry.ReputationScore = clampReputation(entry.ReputationScore)
	clients := c.fingerprintClients[obs.FingerprintID]
	if clients == nil {
		clients = make(map[string]time.Time)
		c.fingerprintClients[obs.FingerprintID] = clients
	}
	clients[obs.ClientIP] = now.Add(time.Duration(ttl) * time.Second)
	entry.DistinctIPs = len(clients)
	c.fingerprints[obs.FingerprintID] = entry
}

func clampReputation(score int) int {
	if score < 0 {
		return 0
	}
	if score > 1200 {
		return 1200
	}
	return score
}

func applyFingerprintDecayLocked(entry *FingerprintObservationAggregate, now time.Time) {
	if entry == nil || entry.UpdatedAt.IsZero() || !now.After(entry.UpdatedAt) {
		return
	}
	elapsed := now.Sub(entry.UpdatedAt)
	scoreDecay := int(elapsed / (20 * time.Second))
	requestDecay := int(elapsed / (45 * time.Second))
	failDecay := int(elapsed / (90 * time.Second))
	sensitiveDecay := int(elapsed / (120 * time.Second))
	entry.ReputationScore = clampReputation(entry.ReputationScore - scoreDecay)
	if entry.Requests > requestDecay {
		entry.Requests -= requestDecay
	} else {
		entry.Requests = 0
	}
	if entry.ChallengeFailures > failDecay {
		entry.ChallengeFailures -= failDecay
	} else {
		entry.ChallengeFailures = 0
	}
	if entry.SensitiveHits > sensitiveDecay {
		entry.SensitiveHits -= sensitiveDecay
	} else {
		entry.SensitiveHits = 0
	}
}

func (c *Controller) applyAutoModeFromObservationsLocked(now time.Time) (Snapshot, bool) {
	metrics := c.metricsFromObservationsLocked(now)
	prevMode := c.currentMode
	nextMode, reasons := policy.DecideNextMode(c.cfg, c.currentMode, metrics)
	if nextMode == prevMode {
		return Snapshot{}, false
	}
	c.currentMode = nextMode
	c.reason = joinReasons(reasons)
	c.lastUpdated = now
	c.recordVersion("cluster_auto_mode", c.reason)
	return Snapshot{
		CurrentMode: c.currentMode,
		Reason:      c.reason,
		LastUpdated: c.lastUpdated,
		Effective:   policy.Compile(c.cfg, c.currentMode),
	}, true
}

func (c *Controller) metricsFromObservationsLocked(now time.Time) policy.ObservedMetrics {
	totalRequests := 0
	totalChallengeFails := 0
	maxWindowSeconds := 1
	for _, entry := range c.observations {
		if !entry.ExpiresAt.After(now) {
			continue
		}
		totalRequests += entry.Requests
		totalChallengeFails += entry.ChallengeFailures
		if c.cfg.Cluster.ObservationWindowSeconds > maxWindowSeconds {
			maxWindowSeconds = c.cfg.Cluster.ObservationWindowSeconds
		}
	}
	hotFingerprints := 0
	maxFanout := 0
	for _, entry := range c.fingerprints {
		if !entry.ExpiresAt.After(now) {
			continue
		}
		if entry.ReputationScore >= 180 || entry.ChallengeFailures >= 4 || entry.DistinctIPs >= 3 {
			hotFingerprints++
		}
		if entry.DistinctIPs > maxFanout {
			maxFanout = entry.DistinctIPs
		}
	}
	challengeFailRatio := 0.0
	if totalRequests > 0 {
		challengeFailRatio = float64(totalChallengeFails) / float64(totalRequests)
	}
	clusterRPS := float64(totalRequests) / float64(maxWindowSeconds)
	baselineRPS := float64(c.cfg.RateLimit.RequestsPerSecond)
	if baselineRPS <= 0 {
		baselineRPS = 1
	}
	return policy.ObservedMetrics{
		RPSMultiplier:      clusterRPS / baselineRPS,
		ChallengeFailRatio: challengeFailRatio,
		FingerprintBursts:  hotFingerprints,
		FingerprintFanout:  maxFanout,
	}
}

func decisionStrength(action string) int {
	switch action {
	case "soft_challenge":
		return 1
	case "pow_challenge":
		return 2
	case "temporary_ban":
		return 3
	case "drop_at_xdp":
		return 4
	default:
		return 0
	}
}

func (c *Controller) loadState() bool {
	if c.statePath == "" {
		return false
	}
	raw, err := os.ReadFile(c.statePath)
	if err != nil {
		return false
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		return false
	}
	if state.CurrentMode == "" {
		return false
	}
	c.currentMode = state.CurrentMode
	c.reason = defaultString(state.Reason, c.reason)
	if !state.LastUpdated.IsZero() {
		c.lastUpdated = state.LastUpdated
	}
	c.audit = state.Audit
	if state.Nodes != nil {
		c.nodes = state.Nodes
	}
	if state.Versions != nil {
		c.versions = state.Versions
	}
	if state.Decisions != nil {
		c.decisions = state.Decisions
	}
	if c.nodes == nil {
		c.nodes = make(map[string]NodeRegistration)
	}
	if c.decisions == nil {
		c.decisions = make(map[string]SharedDecision)
	}
	if c.observations == nil {
		c.observations = make(map[string]ObservationAggregate)
	}
	if c.fingerprints == nil {
		c.fingerprints = make(map[string]FingerprintObservationAggregate)
	}
	if c.fingerprintClients == nil {
		c.fingerprintClients = make(map[string]map[string]time.Time)
	}
	return true
}

func (c *Controller) persistLocked() error {
	if c.statePath == "" {
		return nil
	}
	state := persistedState{
		CurrentMode: c.currentMode,
		Reason:      c.reason,
		LastUpdated: c.lastUpdated,
		Audit:       c.audit,
		Nodes:       c.nodes,
		Versions:    c.versions,
		Decisions:   c.decisions,
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0o755); err != nil {
		return err
	}
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.statePath)
}

func decisionID(clientIP, action string, createdAt time.Time) string {
	return fmt.Sprintf("%s|%s|%d", clientIP, action, createdAt.UnixNano())
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "no evaluation reason"
	}
	out := reasons[0]
	for i := 1; i < len(reasons); i++ {
		out += "; " + reasons[i]
	}
	return out
}
