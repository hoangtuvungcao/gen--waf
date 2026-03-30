package server

import (
	"encoding/json"
	"net/http"

	"genwaf/internal/controller"
	"genwaf/internal/observability"
	"genwaf/internal/policy"
)

type Server struct {
	controller         *controller.Controller
	prometheusExporter *observability.PrometheusExporter
}

func New(ctrl *controller.Controller) *Server {
	return &Server{
		controller:         ctrl,
		prometheusExporter: observability.NewPrometheusExporter(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/metrics", s.prometheusExporter.HTTPHandler())
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/effective", s.handleEffective)
	mux.HandleFunc("/v1/config/current", s.handleConfigCurrent)
	mux.HandleFunc("/v1/config/versions", s.handleConfigVersions)
	mux.HandleFunc("/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/v1/simulate", s.handleSimulate)
	mux.HandleFunc("/v1/mode", s.handleMode)
	mux.HandleFunc("/v1/audit", s.handleAudit)
	mux.HandleFunc("/v1/nodes", s.handleNodes)
	mux.HandleFunc("/v1/nodes/register", s.handleRegisterNode)
	mux.HandleFunc("/v1/nodes/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("/v1/cluster/bundle", s.handleClusterBundle)
	mux.HandleFunc("/v1/cluster/decisions", s.handleClusterDecisions)
	mux.HandleFunc("/v1/cluster/observations", s.handleClusterObservations)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// UpdateMetrics refreshes the Prometheus exporter snapshot
// Call this periodically from the main server loop
func (s *Server) UpdateMetrics(snapshot observability.MetricsSnapshot) {
	s.prometheusExporter.UpdateMetrics(snapshot)
}

// PrometheusExporter exposes the metrics handler for testing/inspection
func (s *Server) PrometheusExporter() *observability.PrometheusExporter {
	return s.prometheusExporter
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Status())
}

func (s *Server) handleEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Status().Effective)
}

func (s *Server) handleConfigCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.CurrentVersion())
}

func (s *Server) handleConfigVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Versions())
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var metrics policy.ObservedMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		writeError(w, http.StatusBadRequest, "invalid metrics payload")
		return
	}

	writeJSON(w, http.StatusOK, s.controller.Evaluate(metrics))
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var metrics policy.ObservedMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		writeError(w, http.StatusBadRequest, "invalid metrics payload")
		return
	}

	writeJSON(w, http.StatusOK, s.controller.Simulate(metrics))
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid mode payload")
		return
	}

	snapshot, err := s.controller.SetMode(req.Mode, req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.AuditTrail())
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Nodes())
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var node controller.NodeRegistration
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		writeError(w, http.StatusBadRequest, "invalid node payload")
		return
	}
	if node.NodeID == "" {
		writeError(w, http.StatusBadRequest, "node_id must not be empty")
		return
	}

	writeJSON(w, http.StatusOK, s.controller.RegisterNode(node))
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var hb controller.NodeHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeError(w, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	node, err := s.controller.HeartbeatNode(hb)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleClusterBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Bundle())
}

func (s *Server) handleClusterDecisions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.controller.SharedDecisions())
	case http.MethodPost:
		var req controller.DecisionInput
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid decision payload")
			return
		}
		decision, err := s.controller.PublishDecision(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, decision)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleClusterObservations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.controller.ObservationState())
	case http.MethodPost:
		var req controller.ObservationBatch
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid observation payload")
			return
		}
		result, err := s.controller.PublishObservations(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
