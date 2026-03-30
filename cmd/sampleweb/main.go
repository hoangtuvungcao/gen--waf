package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type apiResponse struct {
	App       string `json:"app"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

const brandLogoSVG = `<svg viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="sampleweb-surface" x1="76" y1="58" x2="438" y2="454" gradientUnits="userSpaceOnUse">
      <stop stop-color="#091426"/>
      <stop offset="1" stop-color="#183556"/>
    </linearGradient>
    <linearGradient id="sampleweb-stream" x1="112" y1="146" x2="402" y2="346" gradientUnits="userSpaceOnUse">
      <stop stop-color="#1FD5A4"/>
      <stop offset="1" stop-color="#4B7CFF"/>
    </linearGradient>
    <linearGradient id="sampleweb-core" x1="218" y1="176" x2="302" y2="326" gradientUnits="userSpaceOnUse">
      <stop stop-color="#F7FCFF"/>
      <stop offset="1" stop-color="#B9DCFF"/>
    </linearGradient>
    <radialGradient id="sampleweb-aura" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(256 256) rotate(90) scale(170)">
      <stop stop-color="#6BC7FF" stop-opacity="0.28"/>
      <stop offset="0.7" stop-color="#3B82F6" stop-opacity="0.08"/>
      <stop offset="1" stop-color="#3B82F6" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="512" height="512" rx="124" fill="#F7FBFF"/>
  <rect x="42" y="42" width="428" height="428" rx="110" fill="url(#sampleweb-surface)"/>
  <circle cx="256" cy="256" r="162" fill="url(#sampleweb-aura)"/>
  <circle cx="256" cy="256" r="112" stroke="url(#sampleweb-stream)" stroke-width="36"/>
  <circle cx="256" cy="256" r="78" fill="#10233A" fill-opacity="0.96"/>
  <rect x="110" y="149" width="150" height="28" rx="14" fill="url(#sampleweb-stream)"/>
  <rect x="94" y="242" width="166" height="28" rx="14" fill="url(#sampleweb-stream)" fill-opacity="0.94"/>
  <rect x="110" y="335" width="150" height="28" rx="14" fill="url(#sampleweb-stream)" fill-opacity="0.8"/>
  <rect x="292" y="242" width="126" height="28" rx="14" fill="url(#sampleweb-stream)"/>
  <rect x="214" y="176" width="84" height="160" rx="30" fill="url(#sampleweb-core)"/>
  <rect x="240" y="206" width="32" height="100" rx="16" fill="#10233A"/>
  <circle cx="158" cy="110" r="12" fill="#D9EDFF" fill-opacity="0.9"/>
  <circle cx="374" cy="126" r="10" fill="#1FD5A4" fill-opacity="0.95"/>
  <circle cx="356" cy="382" r="14" fill="#D9EDFF" fill-opacity="0.78"/>
</svg>`

func main() {
	listen := flag.String("listen", ":8081", "listen address")
	name := flag.String("name", "sample-web", "instance name")
	flag.Parse()

	logger := log.New(os.Stdout, "[sampleweb] ", log.LstdFlags)
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"app":    *name,
		})
	})

	mux.HandleFunc("/api/hello", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiResponse{
			App:       *name,
			Message:   "xin chào từ website demo của GEN WAF",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=30")
		fmt.Fprintf(w, `(function () {
  function attachInstance() {
    if (!document.body) {
      return false;
    }
    document.body.dataset.instance = %q;
    return true;
  }
  if (!attachInstance()) {
    document.addEventListener("DOMContentLoaded", attachInstance, { once: true });
  }
})();
`, *name)
	})

	mux.HandleFunc("/static/genwaf-logo.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = fmt.Fprint(w, brandLogoSVG)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		title := "GEN WAF Demo"
		eyebrow := "Đã bảo vệ"
		lead := "Trang mẫu tối giản để kiểm tra trải nghiệm sau lớp bảo vệ của GEN WAF."
		cta := "Mọi thứ đang hoạt động ổn định"
		if strings.HasPrefix(r.URL.Path, "/login") {
			title = "Đăng nhập"
			eyebrow = "Khu vực nhạy cảm"
			lead = "Đường dẫn này thường được dùng để kiểm tra CAPTCHA nhấn giữ và challenge tự động."
			cta = "Luồng đăng nhập đã sẵn sàng"
		}
		if strings.HasPrefix(r.URL.Path, "/pricing") {
			title = "Bảng giá"
			eyebrow = "Trang tĩnh"
			lead = "Trang này phù hợp để kiểm tra cache, route thông thường và trải nghiệm sau khi vượt xác minh."
			cta = "Sẵn sàng cho website thật"
		}

		page := strings.NewReplacer(
			"__TITLE__", title,
			"__INSTANCE__", *name,
			"__PATH__", r.URL.Path,
			"__EYEBROW__", eyebrow,
			"__LEAD__", lead,
			"__CTA__", cta,
			"__TIME__", time.Now().UTC().Format(time.RFC3339),
		).Replace(`<!doctype html>
<html lang="vi">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>__TITLE__</title>
    <link rel="icon" href="/static/genwaf-logo.svg" type="image/svg+xml">
    <script defer src="/static/app.js"></script>
    <style>
      :root {
        color-scheme: light;
        --bg-a: #f8fbff;
        --bg-b: #eef4f8;
        --ink: #14263d;
        --muted: #5d7388;
        --line: rgba(20, 38, 61, 0.08);
        --brand-ink: #10233a;
        --brand-a: #1fbf8f;
        --brand-b: #2d6df6;
        --card: rgba(255, 255, 255, 0.94);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Inter, ui-sans-serif, system-ui, sans-serif;
        color: var(--ink);
        text-align: center;
        background:
          radial-gradient(circle at top left, rgba(31,191,143,0.16), transparent 24%),
          radial-gradient(circle at top right, rgba(45,109,246,0.14), transparent 28%),
          linear-gradient(180deg, var(--bg-a), var(--bg-b));
      }
      .shell {
        min-height: 100vh;
        width: min(940px, calc(100vw - 32px));
        margin: 0 auto;
        padding: 24px 0 40px;
      }
      .nav, .hero, .mini-grid { display: grid; gap: 16px; }
      .nav {
        grid-template-columns: 1fr auto;
        align-items: center;
        margin-bottom: 18px;
      }
      .brand {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
      }
      .logo {
        width: 58px;
        height: 58px;
        flex: 0 0 58px;
      }
      .logo img {
        display: block;
        width: 100%;
        height: 100%;
      }
      .brand-meta small {
        display: block;
        color: var(--muted);
        font-size: 0.84rem;
      }
      .brand-meta strong {
        display: block;
        color: var(--brand-ink);
        font-size: 1rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .brand-meta {
        text-align: left;
      }
      .hero {
        grid-template-columns: 1fr;
      }
      .card {
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 30px;
        padding: 28px;
        box-shadow: 0 20px 52px rgba(17, 24, 39, 0.08);
      }
      .hero-main {
        display: grid;
        justify-items: center;
      }
      .eyebrow {
        display: inline-flex;
        align-items: center;
        padding: 7px 12px;
        border-radius: 999px;
        background: rgba(45,109,246,0.09);
        color: #2557c7;
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.01em;
        margin-bottom: 12px;
      }
      h1 {
        font-size: clamp(2rem, 4vw, 3.5rem);
        line-height: 1;
        margin: 0 0 12px;
        letter-spacing: -0.04em;
      }
      p {
        color: var(--muted);
        line-height: 1.7;
        margin: 0;
      }
      .hero-copy {
        max-width: 58ch;
        margin: 0 auto;
      }
      .chip-row {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 12px;
        margin-top: 18px;
        width: 100%;
      }
      .chip {
        border-radius: 18px;
        padding: 14px 16px;
        background: rgba(246, 249, 252, 0.92);
        border: 1px solid var(--line);
        text-align: left;
      }
      .chip strong {
        display: block;
        margin-bottom: 6px;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #688099;
      }
      .cta-row {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 22px;
        justify-content: center;
      }
      .btn {
        text-decoration: none;
        border-radius: 999px;
        padding: 12px 18px;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
      }
      .btn-primary {
        color: white;
        background: linear-gradient(90deg, var(--brand-a), var(--brand-b));
        box-shadow: 0 12px 24px rgba(45,109,246,0.16);
      }
      .btn-muted {
        color: var(--ink);
        background: rgba(255,255,255,0.75);
        border: 1px solid var(--line);
      }
      .summary {
        display: grid;
        gap: 12px;
        margin-top: 18px;
        width: 100%;
      }
      .summary-card {
        padding: 16px 18px;
        border-radius: 20px;
        background: linear-gradient(180deg, rgba(255,255,255,0.9), rgba(239,246,255,0.9));
        border: 1px solid var(--line);
        text-align: left;
      }
      .summary-card strong {
        display: block;
        font-size: 1.15rem;
        margin-bottom: 6px;
      }
      .mini-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        margin-top: 16px;
      }
      .mini-grid .card {
        text-align: left;
      }
      .mono {
        font-family: ui-monospace, SFMono-Regular, monospace;
        color: #16324f;
      }
      .footer-note {
        margin-top: 18px;
        text-align: center;
        color: var(--muted);
        font-size: 0.92rem;
      }
      @media (max-width: 860px) {
        .chip-row, .mini-grid { grid-template-columns: 1fr; }
        .nav { grid-template-columns: 1fr; }
        .brand-meta {
          text-align: left;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <header class="nav">
        <div class="brand">
          <div class="logo">
            <img src="/static/genwaf-logo.svg" alt="GEN WAF logo">
          </div>
          <div class="brand-meta">
            <strong>GEN WAF</strong>
            <small>Protective reverse proxy demo · node __INSTANCE__</small>
          </div>
        </div>
        <div class="mono">__PATH__</div>
      </header>

      <section class="hero">
        <article class="card hero-main">
          <div class="eyebrow">__EYEBROW__</div>
          <h1>__TITLE__</h1>
          <p class="hero-copy">__LEAD__</p>
          <div class="cta-row">
            <a class="btn btn-primary" href="/login">Mở trang đăng nhập</a>
            <a class="btn btn-muted" href="/pricing">Xem trang tĩnh</a>
          </div>
          <div class="chip-row">
            <div class="chip">
              <strong>Edge</strong>
              <span>Cloudflare → GEN WAF → backend</span>
            </div>
            <div class="chip">
              <strong>Bảo vệ</strong>
              <span>Challenge, CAPTCHA, WAF, rate-limit</span>
            </div>
            <div class="chip">
              <strong>Trạng thái</strong>
              <span>__CTA__</span>
            </div>
          </div>
          <div class="summary">
            <div class="summary-card">
              <strong>Đường dẫn hiện tại</strong>
              <span class="mono">__PATH__</span>
            </div>
            <div class="summary-card">
              <strong>Thời gian dựng trang</strong>
              <span class="mono">__TIME__</span>
            </div>
          </div>
        </article>
      </section>

      <section class="mini-grid">
        <article class="card">
          <p>Trang mẫu này được giữ thật gọn để người dùng nhìn thoải mái và để dễ benchmark.</p>
        </article>
        <article class="card">
          <p>Nếu bạn vào <span class="mono">/login</span>, hệ thống sẽ kiểm tra CAPTCHA hoặc challenge tùy chế độ phòng thủ.</p>
        </article>
      </section>

      <div class="footer-note">
        Giao diện này cố ý tối giản để tập trung vào trải nghiệm và giảm chi phí render.
      </div>
    </div>
  </body>
</html>`)
		fmt.Fprint(w, page)
	})

	logger.Printf("listening on %s as %s", *listen, *name)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		logger.Fatal(err)
	}
}
