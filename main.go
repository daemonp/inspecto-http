// Package main is inspecto-http, a DEBUGGING TOOL that exposes request headers,
// cookies, TLS metadata, proxy headers, and process environment variables over
// an unauthenticated HTTP API.
//
// Intended deployment: constrained Docker/Kubernetes networks (e.g. ephemeral
// debug pods, internal-only Services). Do not expose this service on a public
// ingress or shared network. Name-based masking of some env keys and cookie
// names is best-effort only and is not a security boundary.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

//go:embed templates
var templateFS embed.FS

var (
	indexTmpl = template.Must(template.ParseFS(templateFS, "templates/index.html"))

	// Best-effort redaction only — see package comment.
	sensitiveEnvKey = regexp.MustCompile(`(?i)(key|token|secret|password|credential)`)
	sensitiveCookie = regexp.MustCompile(`(?i)(token|session|auth|key|secret|password|credential)`)
)

// debugInfo is the JSON payload for GET /api/debug-info.
// Field names match the frontend tab keys (lowercased labels).
type debugInfo struct {
	Headers     map[string]string `json:"headers"`
	Environment map[string]string `json:"environment"`
	Request     map[string]string `json:"request"`
	Cloudflare  map[string]string `json:"cloudflare"`
	Traefik     map[string]string `json:"traefik"`
	Remote      map[string]string `json:"remote"`
	Server      map[string]string `json:"server"`
	TLS         map[string]string `json:"tls"`
	Cookies     []cookieInfo      `json:"cookies"`
}

type cookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Expires  string `json:"expires"`
	MaxAge   int    `json:"maxAge"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleRoot)
	mux.HandleFunc("GET /api/debug-info", handleDebugInfo)

	port := cmp.Or(os.Getenv("PORT"), "8000")
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("server starting", "port", port, "note", "debug tool — keep internal")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if err := indexTmpl.Execute(w, nil); err != nil {
		// Headers/body may already have been written; do not call http.Error.
		slog.Error("template execute", "err", err)
	}
}

func handleDebugInfo(w http.ResponseWriter, r *http.Request) {
	info := debugInfo{
		Headers:     getHeaders(r),
		Environment: getEnv(),
		Request:     getRequestInfo(r),
		Cloudflare:  getCloudflareInfo(r),
		Traefik:     getTraefikInfo(r),
		Remote:      getRemoteInfo(r),
		Server:      getServerInfo(r),
		TLS:         getTLSInfo(r),
		Cookies:     getCookieInfo(r),
	}
	writeJSON(w, http.StatusOK, info)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode", "err", err)
	}
}

func getHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		if name == "Cookie" {
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	return headers
}

func getEnv() map[string]string {
	environ := os.Environ()
	env := make(map[string]string, len(environ))
	for _, e := range environ {
		key, value, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if sensitiveEnvKey.MatchString(key) {
			value = maskSensitiveValue(value)
		}
		env[key] = value
	}
	return env
}

func maskSensitiveValue(value string) string {
	if value == "" {
		return ""
	}
	// Fixed-length mask avoids leaking secret length.
	return "********"
}

func getRequestInfo(r *http.Request) map[string]string {
	return map[string]string{
		"Method":     r.Method,
		"URL":        r.URL.String(),
		"Protocol":   r.Proto,
		"Host":       r.Host,
		"RemoteAddr": r.RemoteAddr,
		"RequestURI": r.RequestURI,
	}
}

func getCloudflareInfo(r *http.Request) map[string]string {
	cfHeaders := make(map[string]string)
	for name, values := range r.Header {
		if strings.HasPrefix(name, "Cf-") || strings.HasPrefix(name, "X-Cloudflare-") {
			cfHeaders[name] = strings.Join(values, ", ")
		}
	}
	return cfHeaders
}

func getTraefikInfo(r *http.Request) map[string]string {
	keys := []string{
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Real-IP",
		"X-Forwarded-Server",
		"X-Forwarded-User",
		"X-Forwarded-Group",
		"X-Forwarded-Uri",
		"X-Original-URL",
	}
	traefikHeaders := make(map[string]string)
	for _, key := range keys {
		if v := r.Header.Get(key); v != "" {
			traefikHeaders[key] = v
		}
	}
	return traefikHeaders
}

func getRemoteInfo(r *http.Request) map[string]string {
	info := map[string]string{
		"RemoteAddr": r.RemoteAddr,
	}
	if ua := r.UserAgent(); ua != "" {
		info["UserAgent"] = ua
	}
	if ref := r.Referer(); ref != "" {
		info["Referer"] = ref
	}
	return info
}

func getServerInfo(r *http.Request) map[string]string {
	info := map[string]string{
		"ServerProtocol": r.Proto,
	}
	if sw := os.Getenv("SERVER_SOFTWARE"); sw != "" {
		info["ServerSoftware"] = sw
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		info["Hostname"] = h
	}
	return info
}

func getTLSInfo(r *http.Request) map[string]string {
	if r.TLS == nil {
		return map[string]string{"TLS": "Not used"}
	}
	return map[string]string{
		"TLS Version":      tlsVersionString(r.TLS.Version),
		"Cipher Suite":     tls.CipherSuiteName(r.TLS.CipherSuite),
		"Server Name":      r.TLS.ServerName,
		"Negotiated Proto": r.TLS.NegotiatedProtocol,
	}
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func getCookieInfo(r *http.Request) []cookieInfo {
	cookies := r.Cookies()
	out := make([]cookieInfo, 0, len(cookies))
	for _, c := range cookies {
		value := c.Value
		if sensitiveCookie.MatchString(c.Name) {
			value = maskSensitiveValue(value)
		}
		out = append(out, cookieInfo{
			Name:     c.Name,
			Value:    value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  formatTime(c.Expires),
			MaxAge:   c.MaxAge,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: formatSameSite(c.SameSite),
		})
	}
	return out
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "Not set"
	}
	return t.Format(time.RFC3339)
}

func formatSameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Not set"
	}
}
