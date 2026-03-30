package server

import (
	"html/template"
	"net/http"
	"time"

	"genwaf/internal/controller"
)

type dashboardData struct {
	Now          time.Time
	Status       controller.Snapshot
	Current      controller.ConfigVersion
	Versions     []controller.ConfigVersion
	Nodes        []controller.NodeRegistration
	Decisions    []controller.SharedDecision
	Observations []controller.ObservationAggregate
	Fingerprints []controller.FingerprintObservationAggregate
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="vi">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GEN WAF Control Center</title>
    <style>
      :root{color-scheme:light;--ink:#12263d;--muted:#64788d;--line:rgba(18,38,61,.08);--card:rgba(255,255,255,.96);--brand-a:#1fd09a;--brand-b:#2c72ff}
      *{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:var(--ink);background:
      radial-gradient(circle at top left,rgba(31,208,154,.14),transparent 24%),
      radial-gradient(circle at top right,rgba(44,114,255,.14),transparent 26%),linear-gradient(180deg,#f8fbff,#edf3f8)}
      .shell{width:min(1180px,calc(100vw - 32px));margin:0 auto;padding:28px 0 42px}.hero,.grid{display:grid;gap:16px}
      .hero{grid-template-columns:1.1fr .9fr;margin-bottom:18px}.card{background:var(--card);border:1px solid var(--line);border-radius:30px;padding:24px;box-shadow:0 22px 60px rgba(15,23,42,.08)}
      .brand{display:flex;align-items:center;gap:14px}.logo{width:58px;height:58px;border-radius:18px;background:linear-gradient(135deg,var(--brand-a),var(--brand-b));display:grid;place-items:center;box-shadow:0 14px 30px rgba(44,114,255,.18)}
      .logo strong{color:white;font-size:1.1rem;letter-spacing:.12em}.brand-meta strong{display:block;font-size:1rem;letter-spacing:.18em;text-transform:uppercase}.brand-meta span{display:block;color:var(--muted);margin-top:4px}
      h1{margin:16px 0 10px;font-size:clamp(2rem,4vw,3.2rem);line-height:1.02;letter-spacing:-.04em}.lede{margin:0;color:var(--muted);line-height:1.7;max-width:56ch}
      .stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.stat{padding:16px 18px;border-radius:22px;background:linear-gradient(180deg,#132239,#1a3251);color:#edf4fb}
      .stat small{display:block;color:#b7cadb;text-transform:uppercase;letter-spacing:.08em;font-size:.75rem}.stat strong{display:block;margin-top:8px;font-size:1.55rem}
      .grid{grid-template-columns:repeat(2,minmax(0,1fr))}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:10px 0;border-bottom:1px solid var(--line);font-size:.94rem;vertical-align:top}
      .table th{font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}.empty{color:var(--muted);font-style:italic;margin:0}
      .pill{display:inline-flex;padding:6px 10px;border-radius:999px;background:rgba(44,114,255,.08);color:#2456c6;font-weight:700;font-size:.78rem}
      .mono{font-family:ui-monospace,SFMono-Regular,monospace}
      @media (max-width:980px){.hero,.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
      @media (max-width:640px){.stats{grid-template-columns:1fr}}
    </style>
  </head>
  <body>
    <div class="shell">
      <section class="hero">
        <article class="card">
          <div class="brand">
            <div class="logo"><strong>GW</strong></div>
            <div class="brand-meta">
              <strong>GEN WAF</strong>
              <span>Control Center · lightweight operator dashboard</span>
            </div>
          </div>
          <h1>Mode {{.Status.CurrentMode}}</h1>
          <p class="lede">{{.Status.Reason}}</p>
          <p class="lede">Updated at {{.Status.LastUpdated.Format "2006-01-02 15:04:05 UTC"}}</p>
        </article>
        <aside class="card">
          <div class="stats">
            <div class="stat"><small>Config Version</small><strong>{{.Current.Version}}</strong></div>
            <div class="stat"><small>Nodes</small><strong>{{len .Nodes}}</strong></div>
            <div class="stat"><small>Decisions</small><strong>{{len .Decisions}}</strong></div>
            <div class="stat"><small>Observations</small><strong>{{len .Observations}}</strong></div>
            <div class="stat"><small>Fingerprints</small><strong>{{len .Fingerprints}}</strong></div>
          </div>
        </aside>
      </section>

      <section class="grid">
        <article class="card">
          <div class="pill">Nodes</div>
          {{if .Nodes}}
          <table class="table">
            <thead><tr><th>ID</th><th>Address</th><th>Mode</th><th>Version</th></tr></thead>
            <tbody>
            {{range .Nodes}}
              <tr><td class="mono">{{.NodeID}}</td><td>{{.Address}}</td><td>{{.LastAckMode}}</td><td>{{.Version}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{else}}<p class="empty">Chưa có node nào đăng ký.</p>{{end}}
        </article>

        <article class="card">
          <div class="pill">Shared Decisions</div>
          {{if .Decisions}}
          <table class="table">
            <thead><tr><th>Client</th><th>Fingerprint</th><th>Action</th><th>Reason</th></tr></thead>
            <tbody>
            {{range .Decisions}}
              <tr><td class="mono">{{.ClientIP}}</td><td class="mono">{{.FingerprintID}}</td><td>{{.Action}}</td><td>{{.Reason}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{else}}<p class="empty">Chưa có shared decision đang hoạt động.</p>{{end}}
        </article>

        <article class="card">
          <div class="pill">Observation Feed</div>
          {{if .Observations}}
          <table class="table">
            <thead><tr><th>Client</th><th>Fingerprint</th><th>Req</th><th>Challenge Fail</th><th>Reputation</th></tr></thead>
            <tbody>
            {{range .Observations}}
              <tr><td class="mono">{{.ClientIP}}</td><td class="mono">{{.FingerprintID}}</td><td>{{.Requests}}</td><td>{{.ChallengeFailures}}</td><td>{{.ReputationScore}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{else}}<p class="empty">Chưa có observation nào.</p>{{end}}
        </article>

        <article class="card">
          <div class="pill">Hot Fingerprints</div>
          {{if .Fingerprints}}
          <table class="table">
            <thead><tr><th>Fingerprint</th><th>TLS Source</th><th>Bot Score</th><th>IPs</th><th>Req</th><th>Challenge Fail</th><th>Reputation</th></tr></thead>
            <tbody>
            {{range .Fingerprints}}
              <tr><td class="mono">{{.FingerprintID}}</td><td>{{.TLSFingerprintSource}}</td><td>{{.EdgeBotScore}}</td><td>{{.DistinctIPs}}</td><td>{{.Requests}}</td><td>{{.ChallengeFailures}}</td><td>{{.ReputationScore}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{else}}<p class="empty">Chưa có fingerprint nào nóng.</p>{{end}}
        </article>

        <article class="card">
          <div class="pill">Recent Versions</div>
          {{if .Versions}}
          <table class="table">
            <thead><tr><th>Version</th><th>Mode</th><th>Reason</th></tr></thead>
            <tbody>
            {{range .Versions}}
              <tr><td>#{{.Version}}</td><td>{{.Mode}}</td><td>{{.Reason}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{else}}<p class="empty">Chưa có lịch sử version.</p>{{end}}
        </article>
      </section>
    </div>
  </body>
</html>`))

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.controller.Status().Effective.DashboardEnabled {
		http.NotFound(w, r)
		return
	}
	data := dashboardData{
		Now:          time.Now().UTC(),
		Status:       s.controller.Status(),
		Current:      s.controller.CurrentVersion(),
		Versions:     s.controller.Versions(),
		Nodes:        s.controller.Nodes(),
		Decisions:    s.controller.SharedDecisions(),
		Observations: s.controller.ObservationState(),
		Fingerprints: s.controller.FingerprintState(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
