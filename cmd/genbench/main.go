package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type result struct {
	latency time.Duration
	status  int
	err     error
}

type benchmarkReport struct {
	Target            string         `json:"target"`
	Targets           []string       `json:"targets,omitempty"`
	Protocol          string         `json:"protocol"`
	HostHeader        string         `json:"host_header,omitempty"`
	Concurrency       int            `json:"concurrency"`
	Duration          string         `json:"duration"`
	RequestsSent      uint64         `json:"requests_sent"`
	RequestsCompleted uint64         `json:"requests_completed"`
	Errors            uint64         `json:"errors"`
	ThroughputRPS     float64        `json:"throughput_rps"`
	LatencyAvg        string         `json:"latency_avg"`
	LatencyP50        string         `json:"latency_p50"`
	LatencyP95        string         `json:"latency_p95"`
	LatencyP99        string         `json:"latency_p99"`
	StatusCounts      map[int]uint64 `json:"status_counts"`
}

type closeIdler interface {
	CloseIdleConnections()
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func main() {
	target := flag.String("target", "http://127.0.0.1:18090/", "URL cần benchmark")
	targetsCSV := flag.String("targets", "", "Danh sách target phân cách bởi dấu phẩy để benchmark theo round-robin/random")
	protocol := flag.String("protocol", "http1", "Giao thức client: http1, http2, http3")
	host := flag.String("host", "", "Header Host cần gửi")
	clientIP := flag.String("client-ip", "198.51.100.10", "Giá trị cho CF-Connecting-IP")
	clientIPHeader := flag.String("client-ip-header", "", "Header tùy chọn để gửi IP client benchmark thay vì CF-Connecting-IP")
	varyClientIP := flag.Bool("vary-client-ip", false, "Tự xoay IP client để mô phỏng nhiều nguồn gửi khác nhau")
	sendEdgeHeaders := flag.Bool("send-edge-headers", true, "Gửi header edge giả lập Cloudflare trực tiếp tới target")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "Bỏ qua kiểm tra TLS certificate cho lab/dev")
	requestJitterMaxMS := flag.Int("request-jitter-max-ms", 0, "Jitter tối đa trước mỗi request để mô phỏng mạng di động/lossy")
	closeIdleEveryRequest := flag.Bool("close-idle-every-request", false, "Đóng idle connections sau mỗi request để mô phỏng reconnect thường xuyên")
	disableKeepAlives := flag.Bool("disable-keepalives", false, "Tắt keep-alive cho HTTP/1.1")
	concurrency := flag.Int("concurrency", 32, "Số worker chạy song song")
	duration := flag.Duration("duration", 10*time.Second, "Thời gian chạy benchmark")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout mỗi request")
	bodyDiscardLimit := flag.Int64("body-discard-limit", 1<<20, "Số byte tối đa đọc từ response body")
	jsonOutput := flag.Bool("json", false, "In kết quả dưới dạng JSON")
	flag.Parse()

	if *concurrency <= 0 {
		fmt.Fprintln(os.Stderr, "concurrency phải > 0")
		os.Exit(1)
	}

	targets := make([]string, 0, 4)
	if *targetsCSV != "" {
		for _, part := range strings.Split(*targetsCSV, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				targets = append(targets, part)
			}
		}
	}
	if len(targets) == 0 {
		targets = append(targets, *target)
	}

	http1Transport := &http.Transport{
		MaxIdleConns:        *concurrency * 2,
		MaxIdleConnsPerHost: *concurrency * 2,
		MaxConnsPerHost:     *concurrency * 2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		DisableKeepAlives:   *disableKeepAlives,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecureSkipVerify},
		DialContext: (&net.Dialer{
			Timeout:   *timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: *timeout,
		ExpectContinueTimeout: 500 * time.Millisecond,
		ForceAttemptHTTP2:     false,
	}
	defer http1Transport.CloseIdleConnections()

	http2Transport := &http2.Transport{
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: *insecureSkipVerify},
	}

	http3Transport := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: *insecureSkipVerify},
	}
	defer http3Transport.Close()

	var transport http.RoundTripper
	switch *protocol {
	case "http1":
		transport = http1Transport
	case "http2":
		transport = http2Transport
	case "http3":
		transport = http3Transport
	default:
		fmt.Fprintln(os.Stderr, "protocol phải là http1, http2 hoặc http3")
		os.Exit(1)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	results := make(chan result, *concurrency*4)
	var sent uint64
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i+1)*7919))
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ip := *clientIP
				if *varyClientIP {
					ip = fmt.Sprintf("198.51.%d.%d", rng.Intn(200)+1, rng.Intn(250)+1)
				}
				if *requestJitterMaxMS > 0 {
					jitter := time.Duration(rng.Intn(*requestJitterMaxMS)+1) * time.Millisecond
					timer := time.NewTimer(jitter)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
				targetURL := targets[rng.Intn(len(targets))]
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
				if err != nil {
					results <- result{err: err}
					return
				}
				if *host != "" {
					req.Host = *host
				}
				if *disableKeepAlives && *protocol == "http1" {
					req.Close = true
				}
				if *sendEdgeHeaders {
					req.Header.Set("X-Edge-Verified", "cloudflare")
					req.Header.Set("CF-Connecting-IP", ip)
					req.Header.Set("CF-Ray", "genwaf-bench")
				}
				if *clientIPHeader != "" {
					req.Header.Set(*clientIPHeader, ip)
				}
				req.Header.Set("User-Agent", "genwaf-bench/1.0")

				start := time.Now()
				resp, err := client.Do(req)
				atomic.AddUint64(&sent, 1)
				if err != nil {
					results <- result{latency: time.Since(start), err: err}
					continue
				}
				_, _ = io.CopyN(io.Discard, resp.Body, *bodyDiscardLimit)
				_ = resp.Body.Close()
				if *closeIdleEveryRequest {
					if closer, ok := transport.(closeIdler); ok {
						closer.CloseIdleConnections()
					}
				}
				results <- result{latency: time.Since(start), status: resp.StatusCode}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var completed uint64
	var errors uint64
	statusCounts := map[int]uint64{}
	latencies := make([]time.Duration, 0, 16384)
	var latencySum time.Duration

	for res := range results {
		if res.err != nil {
			errors++
			continue
		}
		completed++
		statusCounts[res.status]++
		latencies = append(latencies, res.latency)
		latencySum += res.latency
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	avg := time.Duration(0)
	if completed > 0 {
		avg = time.Duration(int64(latencySum) / int64(completed))
	}

	actualDuration := *duration
	if actualDuration <= 0 {
		actualDuration = time.Second
	}

	report := benchmarkReport{
		Target:            strings.Join(targets, ","),
		Targets:           append([]string(nil), targets...),
		Protocol:          *protocol,
		HostHeader:        *host,
		Concurrency:       *concurrency,
		Duration:          actualDuration.String(),
		RequestsSent:      sent,
		RequestsCompleted: completed,
		Errors:            errors,
		ThroughputRPS:     float64(completed) / actualDuration.Seconds(),
		LatencyAvg:        avg.String(),
		LatencyP50:        percentile(latencies, 0.50).String(),
		LatencyP95:        percentile(latencies, 0.95).String(),
		LatencyP99:        percentile(latencies, 0.99).String(),
		StatusCounts:      statusCounts,
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("GEN WAF Benchmark")
	fmt.Printf("- target: %s\n", report.Target)
	fmt.Printf("- protocol: %s\n", report.Protocol)
	if report.HostHeader != "" {
		fmt.Printf("- host header: %s\n", report.HostHeader)
	}
	fmt.Printf("- concurrency: %d\n", report.Concurrency)
	fmt.Printf("- duration: %s\n", report.Duration)
	fmt.Printf("- requests sent: %d\n", report.RequestsSent)
	fmt.Printf("- requests completed: %d\n", report.RequestsCompleted)
	fmt.Printf("- errors: %d\n", report.Errors)
	fmt.Printf("- throughput: %.2f req/s\n", report.ThroughputRPS)
	fmt.Printf("- latency avg: %s\n", report.LatencyAvg)
	fmt.Printf("- latency p50: %s\n", report.LatencyP50)
	fmt.Printf("- latency p95: %s\n", report.LatencyP95)
	fmt.Printf("- latency p99: %s\n", report.LatencyP99)
	fmt.Println("- status counts:")
	statuses := make([]int, 0, len(report.StatusCounts))
	for code := range report.StatusCounts {
		statuses = append(statuses, code)
	}
	sort.Ints(statuses)
	for _, code := range statuses {
		fmt.Printf("  - %d: %d\n", code, report.StatusCounts[code])
	}
}
