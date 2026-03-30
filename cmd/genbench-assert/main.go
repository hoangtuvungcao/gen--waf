package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// BenchmarkResult represents the output from genbench
type BenchmarkResult struct {
	Target        string         `json:"target"`
	Protocol      string         `json:"protocol"`
	Concurrency   int            `json:"concurrency"`
	Duration      string         `json:"duration"`
	RequestsSent  uint64         `json:"requests_sent"`
	RequestsComp  uint64         `json:"requests_completed"`
	Errors        uint64         `json:"errors"`
	ThroughputRPS float64        `json:"throughput_rps"`
	LatencyAvgMS  float64        `json:"latency_avg_ms"`
	LatencyP50MS  float64        `json:"latency_p50_ms"`
	LatencyP95MS  float64        `json:"latency_p95_ms"`
	LatencyP99MS  float64        `json:"latency_p99_ms"`
	StatusCounts  map[int]uint64 `json:"status_counts"`
}

// BenchmarkThreshold defines performance expectations
type BenchmarkThreshold struct {
	Description      string  `json:"description"`
	Concurrency      int     `json:"concurrency"`
	MinThroughputRPS float64 `json:"min_throughput_rps"`
	MaxLatencyP50MS  float64 `json:"max_latency_p50_ms"`
	MaxLatencyP95MS  float64 `json:"max_latency_p95_ms"`
	MaxLatencyP99MS  float64 `json:"max_latency_p99_ms"`
	MaxErrorRate     float64 `json:"max_error_rate"`
	ExpectedStatuses []int   `json:"expected_status_codes"`
	ErrorBudgetPct   float64 `json:"error_budget_pct"`
}

// ProfileThresholds groups benchmarks by profile
type ProfileThresholds struct {
	Description string                        `json:"description"`
	Benchmarks  map[string]BenchmarkThreshold `json:"benchmarks"`
}

// ThresholdsConfig root structure
type ThresholdsConfig struct {
	Profiles map[string]ProfileThresholds `json:"profiles"`
}

// AssertionResult tracks pass/fail for each check
type AssertionResult struct {
	Name    string
	Passed  bool
	Message string
	Value   string
}

// ValidateResult runs assertions against a benchmark result
func ValidateResult(result BenchmarkResult, threshold BenchmarkThreshold) []AssertionResult {
	var assertions []AssertionResult
	errorRate := float64(result.Errors) / float64(result.RequestsComp)

	// Throughput check
	if result.ThroughputRPS < threshold.MinThroughputRPS {
		assertions = append(assertions, AssertionResult{
			Name:    "Throughput",
			Passed:  false,
			Message: fmt.Sprintf("throughput %.2f RPS below minimum %.2f RPS", result.ThroughputRPS, threshold.MinThroughputRPS),
			Value:   fmt.Sprintf("%.2f", result.ThroughputRPS),
		})
	} else {
		assertions = append(assertions, AssertionResult{
			Name:    "Throughput",
			Passed:  true,
			Message: fmt.Sprintf("throughput %.2f RPS meets minimum %.2f RPS", result.ThroughputRPS, threshold.MinThroughputRPS),
			Value:   fmt.Sprintf("%.2f", result.ThroughputRPS),
		})
	}

	// Latency P50 check
	if result.LatencyP50MS > threshold.MaxLatencyP50MS {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P50",
			Passed:  false,
			Message: fmt.Sprintf("p50 latency %.2f ms exceeds maximum %.2f ms", result.LatencyP50MS, threshold.MaxLatencyP50MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP50MS),
		})
	} else {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P50",
			Passed:  true,
			Message: fmt.Sprintf("p50 latency %.2f ms within limit %.2f ms", result.LatencyP50MS, threshold.MaxLatencyP50MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP50MS),
		})
	}

	// Latency P95 check
	if result.LatencyP95MS > threshold.MaxLatencyP95MS {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P95",
			Passed:  false,
			Message: fmt.Sprintf("p95 latency %.2f ms exceeds maximum %.2f ms", result.LatencyP95MS, threshold.MaxLatencyP95MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP95MS),
		})
	} else {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P95",
			Passed:  true,
			Message: fmt.Sprintf("p95 latency %.2f ms within limit %.2f ms", result.LatencyP95MS, threshold.MaxLatencyP95MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP95MS),
		})
	}

	// Latency P99 check
	if result.LatencyP99MS > threshold.MaxLatencyP99MS {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P99",
			Passed:  false,
			Message: fmt.Sprintf("p99 latency %.2f ms exceeds maximum %.2f ms", result.LatencyP99MS, threshold.MaxLatencyP99MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP99MS),
		})
	} else {
		assertions = append(assertions, AssertionResult{
			Name:    "Latency P99",
			Passed:  true,
			Message: fmt.Sprintf("p99 latency %.2f ms within limit %.2f ms", result.LatencyP99MS, threshold.MaxLatencyP99MS),
			Value:   fmt.Sprintf("%.2f ms", result.LatencyP99MS),
		})
	}

	// Error rate check
	if errorRate > threshold.MaxErrorRate {
		assertions = append(assertions, AssertionResult{
			Name:    "Error Rate",
			Passed:  false,
			Message: fmt.Sprintf("error rate %.2f%% exceeds maximum %.2f%%", errorRate*100, threshold.MaxErrorRate*100),
			Value:   fmt.Sprintf("%.2f%%", errorRate*100),
		})
	} else {
		assertions = append(assertions, AssertionResult{
			Name:    "Error Rate",
			Passed:  true,
			Message: fmt.Sprintf("error rate %.2f%% within limit %.2f%%", errorRate*100, threshold.MaxErrorRate*100),
			Value:   fmt.Sprintf("%.2f%%", errorRate*100),
		})
	}

	return assertions
}

func main() {
	resultFile := flag.String("result", "", "Path to benchmark result JSON file")
	thresholdFile := flag.String("threshold", "", "Path to thresholds config JSON")
	profile := flag.String("profile", "", "Profile name (e.g., edge-baseline, cluster-redis-native)")
	benchmark := flag.String("benchmark", "", "Benchmark name (e.g., http1-passthrough)")
	flag.Parse()

	if *resultFile == "" || *thresholdFile == "" || *profile == "" || *benchmark == "" {
		fmt.Fprintf(os.Stderr, "Usage: genbench-assert -result=<file> -threshold=<file> -profile=<name> -benchmark=<name>\n")
		os.Exit(1)
	}

	// Load benchmark result
	resultData, err := os.ReadFile(*resultFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading result file: %v\n", err)
		os.Exit(1)
	}

	var result BenchmarkResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing result JSON: %v\n", err)
		os.Exit(1)
	}

	// Load thresholds
	thresholdData, err := os.ReadFile(*thresholdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading threshold file: %v\n", err)
		os.Exit(1)
	}

	var thresholds ThresholdsConfig
	if err := json.Unmarshal(thresholdData, &thresholds); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing thresholds JSON: %v\n", err)
		os.Exit(1)
	}

	// Get profile and benchmark thresholds
	profileThresh, ok := thresholds.Profiles[*profile]
	if !ok {
		fmt.Fprintf(os.Stderr, "Profile %q not found in thresholds\n", *profile)
		os.Exit(1)
	}

	benchThresh, ok := profileThresh.Benchmarks[*benchmark]
	if !ok {
		fmt.Fprintf(os.Stderr, "Benchmark %q not found in profile %q\n", *benchmark, *profile)
		os.Exit(1)
	}

	// Run assertions
	assertions := ValidateResult(result, benchThresh)

	// Print results
	fmt.Printf("Benchmark Assertion Results\n")
	fmt.Printf("Profile: %s, Benchmark: %s\n", *profile, *benchmark)
	fmt.Printf("========================================\n")

	failCount := 0
	for _, a := range assertions {
		status := "✓ PASS"
		if !a.Passed {
			status = "✗ FAIL"
			failCount++
		}
		fmt.Printf("%s %s: %s (%s)\n", status, a.Name, a.Message, a.Value)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("Result: %d/%d assertions passed\n", len(assertions)-failCount, len(assertions))

	if failCount > 0 {
		os.Exit(1)
	}
}
