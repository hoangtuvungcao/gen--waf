package brain

import "strings"

type ScoreRequest struct {
	IPReputation       int     `json:"ip_reputation"`
	ASNReputation      int     `json:"asn_reputation"`
	NewConnectionRate  float64 `json:"new_connection_rate"`
	TLSFingerprintRisk int     `json:"tls_fingerprint_risk"`
	HeaderEntropyRisk  int     `json:"header_entropy_risk"`
	RetryPatternRisk   int     `json:"retry_pattern_risk"`
	SessionQuality     int     `json:"session_quality"`
	ChallengeFailRatio float64 `json:"challenge_fail_ratio"`
	CPUPercent         float64 `json:"cpu_percent"`
	ConnectionBacklog  int     `json:"connection_backlog"`
	DirectOriginHits   int     `json:"direct_origin_hits"`
	PathSensitivity    string  `json:"path_sensitivity"`
}

type ScoreResponse struct {
	NetworkScore   int      `json:"network_score"`
	TransportScore int      `json:"transport_score"`
	HTTPScore      int      `json:"http_score"`
	BehaviorScore  int      `json:"behavior_score"`
	SystemScore    int      `json:"system_score"`
	TotalScore     int      `json:"total_score"`
	Decision       string   `json:"decision"`
	Reasons        []string `json:"reasons"`
}

func Score(req ScoreRequest) ScoreResponse {
	var resp ScoreResponse
	var reasons []string

	resp.NetworkScore += clamp(req.IPReputation, 0, 30)
	resp.NetworkScore += clamp(req.ASNReputation, 0, 20)
	if req.NewConnectionRate > 100 {
		resp.NetworkScore += 20
		reasons = append(reasons, "new connection rate is abnormally high")
	}
	if req.DirectOriginHits > 0 {
		resp.NetworkScore += 30
		reasons = append(reasons, "direct origin hits detected")
	}

	resp.TransportScore += clamp(req.TLSFingerprintRisk, 0, 25)
	if req.TLSFingerprintRisk >= 15 {
		reasons = append(reasons, "transport fingerprint looks suspicious")
	}

	resp.HTTPScore += clamp(req.HeaderEntropyRisk, 0, 20)
	resp.HTTPScore += clamp(req.RetryPatternRisk, 0, 20)
	if isSensitive(req.PathSensitivity) {
		resp.HTTPScore += 10
		reasons = append(reasons, "request targets a sensitive path")
	}

	if req.SessionQuality < 50 {
		resp.BehaviorScore += 20
		reasons = append(reasons, "session quality is low")
	}
	if req.ChallengeFailRatio >= 0.6 {
		resp.BehaviorScore += 25
		reasons = append(reasons, "challenge fail ratio is high")
	}

	if req.CPUPercent >= 85 {
		resp.SystemScore += 15
		reasons = append(reasons, "origin cpu pressure is high")
	}
	if req.ConnectionBacklog >= 1000 {
		resp.SystemScore += 20
		reasons = append(reasons, "connection backlog is high")
	}

	resp.TotalScore = resp.NetworkScore + resp.TransportScore + resp.HTTPScore + resp.BehaviorScore + resp.SystemScore
	resp.Decision = decide(resp.TotalScore)
	resp.Reasons = reasons
	if len(resp.Reasons) == 0 {
		resp.Reasons = []string{"traffic looks close to baseline"}
	}
	return resp
}

func decide(score int) string {
	switch {
	case score >= 90:
		return "drop_at_xdp"
	case score >= 70:
		return "temporary_ban"
	case score >= 50:
		return "pow_challenge"
	case score >= 30:
		return "soft_challenge"
	case score >= 15:
		return "shadow_throttle"
	default:
		return "allow"
	}
}

func clamp(v, min, max int) int {
	switch {
	case v < min:
		return min
	case v > max:
		return max
	default:
		return v
	}
}

func isSensitive(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high", "auth", "login", "payment":
		return true
	default:
		return false
	}
}
