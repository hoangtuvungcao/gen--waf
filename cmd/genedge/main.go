package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func main() {
	listenAddr := flag.String("listen", ":8443", "TLS listen address for HTTP/1.1 and HTTP/2")
	upstreamAddr := flag.String("upstream", "http://127.0.0.1:18080", "upstream GEN WAF data-plane URL")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	enableHTTP3 := flag.Bool("http3", true, "enable HTTP/3 over QUIC on the same port number")
	edgeName := flag.String("edge-name", "genedge", "value to send in X-Edge-Verified")
	readHeaderTimeout := flag.Duration("read-header-timeout", 5*time.Second, "read header timeout")
	idleTimeout := flag.Duration("idle-timeout", 60*time.Second, "idle timeout")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("both -cert and -key are required")
	}

	upstreamURL, err := url.Parse(*upstreamAddr)
	if err != nil {
		log.Fatalf("parse upstream: %v", err)
	}

	handler := edgeHandler(upstreamURL, *listenAddr, *edgeName)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "h3"},
	}
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: *readHeaderTimeout,
		IdleTimeout:       *idleTimeout,
		TLSConfig:         tlsConfig,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		log.Fatalf("configure http2: %v", err)
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("genedge listening for HTTP/1.1 + HTTP/2 on %s -> %s", *listenAddr, upstreamURL)
		errCh <- server.ListenAndServeTLS(*certFile, *keyFile)
	}()

	var http3Server *http3.Server
	if *enableHTTP3 {
		http3Server = &http3.Server{
			Addr:    *listenAddr,
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				NextProtos: []string{"h3"},
			},
		}
		go func() {
			log.Printf("genedge listening for HTTP/3 on %s -> %s", *listenAddr, upstreamURL)
			errCh <- http3Server.ListenAndServeTLS(*certFile, *keyFile)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("genedge shutting down on signal %s", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve edge gateway: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	if http3Server != nil {
		_ = http3Server.Shutdown(ctx)
	}
}

func edgeHandler(upstreamURL *url.URL, listenAddr, edgeName string) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			originalHost := pr.In.Host
			pr.SetURL(upstreamURL)
			pr.Out.Host = originalHost
			pr.Out.Header.Set("X-Edge-Verified", edgeName)
			pr.Out.Header.Set("X-GenWAF-Client-IP", forwardedClientIP(pr.In))
			pr.Out.Header.Set("X-GenWAF-Ingress-Protocol", ingressProtocol(pr.In))
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			if originalHost != "" {
				pr.Out.Header.Set("X-Forwarded-Host", originalHost)
			}
			if pr.In.TLS != nil {
				pr.Out.Header.Set("X-GenWAF-TLS-Fingerprint", tlsFingerprint(pr.In))
			}
			pr.Out.Header.Del("X-GenWAF-Benchmark-Client-IP")
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, fmt.Sprintf("edge proxy upstream error: %v", err), http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := ingressProtocol(r)
		w.Header().Set("X-GenWAF-Edge-Protocol", proto)
		if port := portFromListenAddr(listenAddr); port != "" {
			w.Header().Add("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, port))
		}
		proxy.ServeHTTP(w, r)
	})
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func forwardedClientIP(req *http.Request) string {
	remoteIP := clientIPFromRemoteAddr(req.RemoteAddr)
	if benchmarkIP := strings.TrimSpace(req.Header.Get("X-GenWAF-Benchmark-Client-IP")); benchmarkIP != "" && isLocalOrPrivateIP(remoteIP) {
		return benchmarkIP
	}
	return remoteIP
}

func isLocalOrPrivateIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

func ingressProtocol(req *http.Request) string {
	switch {
	case req.ProtoMajor == 3:
		return "h3"
	case req.ProtoMajor == 2:
		return "h2"
	case req.ProtoMajor == 1:
		return "http/1.1"
	default:
		return strings.ToLower(req.Proto)
	}
}

func tlsFingerprint(req *http.Request) string {
	if req.TLS == nil {
		return ""
	}
	parts := []string{
		fmt.Sprintf("version=%d", req.TLS.Version),
		fmt.Sprintf("cipher=%d", req.TLS.CipherSuite),
		fmt.Sprintf("proto=%s", ingressProtocol(req)),
		fmt.Sprintf("server=%s", req.TLS.ServerName),
	}
	if len(req.TLS.PeerCertificates) > 0 {
		parts = append(parts, fmt.Sprintf("peer_cert=%d", len(req.TLS.PeerCertificates)))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "genedge-sha256:" + hex.EncodeToString(sum[:16])
}

func portFromListenAddr(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err == nil {
		return port
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(listenAddr, ":")); err == nil && n > 0 {
		return strconv.Itoa(n)
	}
	return ""
}
