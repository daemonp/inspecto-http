// main.go
package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

//go:embed templates
var templateFS embed.FS

func main() {
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/api/debug-info", handleDebugInfo)

	port := "8000"
	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		http.Error(w, "Failed to parse template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Failed to execute template", http.StatusInternalServerError)
	}
}

func handleDebugInfo(w http.ResponseWriter, r *http.Request) {
	debugInfo := map[string]interface{}{
		"headers":     getHeaders(r),
		"environment": getEnv(),
		"request":     getRequestInfo(r),
		"cloudflare":  getCloudflareInfo(r),
		"traefik":     getTraefikInfo(r),
		"remoteInfo":  getRemoteInfo(r),
		"serverInfo":  getServerInfo(r),
		"tls":         getTLSInfo(r),
		"cookies":     getCookieInfo(r),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(debugInfo)
}

func getHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for name, values := range r.Header {
		if name != "Cookie" { 
			headers[name] = strings.Join(values, ", ")
		}
	}
	return headers
}

func getEnv() map[string]string {
	env := make(map[string]string)
	sensitivePattern := regexp.MustCompile(`(?i)(key|token|secret|password|credential)`)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			key := pair[0]
			value := pair[1]

			if sensitivePattern.MatchString(key) {
				value = maskSensitiveValue(value)
			}

			env[key] = value
		}
	}
	return env
}

func maskSensitiveValue(value string) string {
	return strings.Repeat("X", len(value))
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
		if strings.HasPrefix(name, "Cf-") {
			cfHeaders[name] = strings.Join(values, ", ")
		}
	}
	return cfHeaders
}

func getTraefikInfo(r *http.Request) map[string]string {
	traefikHeaders := map[string]string{
		"X-Forwarded-For":    r.Header.Get("X-Forwarded-For"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Port":   r.Header.Get("X-Forwarded-Port"),
		"X-Real-IP":          r.Header.Get("X-Real-IP"),
		"X-Forwarded-Server": r.Header.Get("X-Forwarded-Server"),
		"X-Forwarded-User":   r.Header.Get("X-Forwarded-User"),
		"X-Forwarded-Group":  r.Header.Get("X-Forwarded-Group"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
		"X-Original-URL":     r.Header.Get("X-Original-URL"),
	}
	return traefikHeaders
}

func getRemoteInfo(r *http.Request) map[string]string {
	return map[string]string{
		"RemoteAddr": r.RemoteAddr,
		"UserAgent":  r.UserAgent(),
		"Referer":    r.Referer(),
	}
}

func getServerInfo(r *http.Request) map[string]string {
	return map[string]string{
		"ServerProtocol": r.Proto,
		"ServerSoftware": os.Getenv("SERVER_SOFTWARE"),
	}
}

func getTLSInfo(r *http.Request) map[string]string {
	if r.TLS == nil {
		return map[string]string{"TLS": "Not used"}
	}
	return map[string]string{
		"TLS Version":      getTLSVersion(r.TLS.Version),
		"Cipher Suite":     tls.CipherSuiteName(r.TLS.CipherSuite),
		"Server Name":      r.TLS.ServerName,
		"Negotiated Proto": r.TLS.NegotiatedProtocol,
	}
}

func getTLSVersion(version uint16) string {
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

func getCookieInfo(r *http.Request) []map[string]string {
	cookies := r.Cookies()
	cookieInfo := make([]map[string]string, len(cookies))

	sensitivePattern := regexp.MustCompile(`(?i)(token|session|auth|key|secret|password|credential)`)

	for i, cookie := range cookies {
		cookieData := map[string]string{
			"Name":     cookie.Name,
			"Value":    cookie.Value,
			"Path":     cookie.Path,
			"Domain":   cookie.Domain,
			"Expires":  formatTime(cookie.Expires),
			"MaxAge":   fmt.Sprintf("%d", cookie.MaxAge),
			"Secure":   fmt.Sprintf("%t", cookie.Secure),
			"HttpOnly": fmt.Sprintf("%t", cookie.HttpOnly),
			"SameSite": formatSameSite(cookie.SameSite),
		}

		if sensitivePattern.MatchString(cookie.Name) {
			cookieData["Value"] = maskSensitiveValue(cookie.Value)
		}

		cookieInfo[i] = cookieData
	}

	return cookieInfo
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
