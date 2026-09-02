package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PatchMon/PatchMon/server-source-code/internal/config"
)

func runSecurityHeaders(t *testing.T, csp, path string) http.Header {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	SecurityHeaders(csp)(next).ServeHTTP(rec, req)
	return rec.Result().Header
}

func TestSecurityHeaders_SetsHardeningHeaders(t *testing.T) {
	t.Parallel()
	h := runSecurityHeaders(t, config.DefaultContentSecurityPolicy, "/api/v1/hosts")

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "SAMEORIGIN",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
		"X-Robots-Tag":            "noindex, nofollow, noarchive, nosnippet",
		"Content-Security-Policy": config.DefaultContentSecurityPolicy,
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// Swagger UI is served with inline scripts, so a 'self'-only policy would
// leave the page blank. Only the CSP is skipped there; the rest still apply.
func TestSecurityHeaders_SkipsCSPForSwaggerUI(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/api-docs", "/api/v1/api-docs/", "/api/v1/api-docs/swagger-ui.css"} {
		h := runSecurityHeaders(t, config.DefaultContentSecurityPolicy, p)
		if got := h.Get("Content-Security-Policy"); got != "" {
			t.Errorf("%s: CSP = %q, want none", p, got)
		}
		if got := h.Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("%s: X-Frame-Options = %q, want SAMEORIGIN", p, got)
		}
	}
}

// CONTENT_SECURITY_POLICY=off resolves to an empty policy, which must mean
// "send no CSP header", not "send an empty header".
func TestSecurityHeaders_EmptyPolicyOmitsHeader(t *testing.T) {
	t.Parallel()
	h := runSecurityHeaders(t, "  ", "/")
	if _, present := h["Content-Security-Policy"]; present {
		t.Errorf("Content-Security-Policy header present, want absent")
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestSecurityHeaders_CustomPolicyIsSentVerbatim(t *testing.T) {
	t.Parallel()
	const custom = "default-src 'none'; img-src https://cdn.example.edu"
	h := runSecurityHeaders(t, custom, "/")
	if got := h.Get("Content-Security-Policy"); got != custom {
		t.Errorf("Content-Security-Policy = %q, want %q", got, custom)
	}
}
