package context

import (
	stdctx "context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// The tests share the package-level allow-list, so they run serially and
// each one restores the unrestricted default when it finishes.
func resetModules(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetSingleContextModules(nil) })
}

func TestHasModule_SingleContextUnrestrictedByDefault(t *testing.T) {
	resetModules(t)
	for _, m := range KnownModules {
		if !HasModule(stdctx.Background(), m) {
			t.Errorf("HasModule(%q) = false with no allow-list, want true", m)
		}
	}
	if got := SingleContextModulesString(); got != "*" {
		t.Errorf("SingleContextModulesString() = %q, want \"*\"", got)
	}
}

func TestSetSingleContextModules_RestrictsAndReportsUnknown(t *testing.T) {
	resetModules(t)
	unknown := SetSingleContextModules([]string{" Patching ", "docker", "patching", "sshterminal", ""})
	if want := []string{"sshterminal"}; !reflect.DeepEqual(unknown, want) {
		t.Errorf("unknown = %v, want %v", unknown, want)
	}

	ctx := stdctx.Background()
	if !HasModule(ctx, "patching") || !HasModule(ctx, "docker") {
		t.Error("listed modules must be allowed")
	}
	for _, m := range []string{"ssh_terminal", "rdp", "ai", "compliance"} {
		if HasModule(ctx, m) {
			t.Errorf("HasModule(%q) = true, want false when not listed", m)
		}
	}
	// Sorted, deduplicated, lower-cased: the string the frontend splits on.
	if got := SingleContextModulesString(); got != "docker,patching" {
		t.Errorf("SingleContextModulesString() = %q, want \"docker,patching\"", got)
	}
}

// A list of only unknown names must not silently fall back to "everything":
// the operator asked for a restriction and got the names wrong.
func TestSetSingleContextModules_OnlyUnknownDisablesAll(t *testing.T) {
	resetModules(t)
	unknown := SetSingleContextModules([]string{"nope", "also_nope"})
	if len(unknown) != 2 {
		t.Fatalf("unknown = %v, want both names", unknown)
	}
	if HasModule(stdctx.Background(), "patching") {
		t.Error("HasModule(patching) = true, want false when the allow-list is empty after dropping unknowns")
	}
	if got := SingleContextModulesString(); got != "" {
		t.Errorf("SingleContextModulesString() = %q, want empty", got)
	}
}

func TestSetSingleContextModules_WildcardAndEmptyRestore(t *testing.T) {
	resetModules(t)
	SetSingleContextModules([]string{"rdp"})
	if HasModule(stdctx.Background(), "patching") {
		t.Fatal("precondition: patching should be disabled")
	}
	SetSingleContextModules([]string{"*"})
	if !HasModule(stdctx.Background(), "patching") {
		t.Error("\"*\" must lift the restriction")
	}
	SetSingleContextModules([]string{"rdp"})
	SetSingleContextModules(nil)
	if !HasModule(stdctx.Background(), "patching") {
		t.Error("nil must lift the restriction")
	}
}

// A registry entry on the request wins over the single-context list, so a
// multi-context deployment is unaffected by ENABLED_MODULES.
func TestHasModule_RegistryEntryIgnoresSingleContextList(t *testing.T) {
	resetModules(t)
	SetSingleContextModules([]string{"docker"})

	mods := "patching"
	ctx := WithEntry(stdctx.Background(), &Entry{Modules: &mods})
	if !HasModule(ctx, "patching") {
		t.Error("entry-listed module must be allowed regardless of the single-context list")
	}
	if HasModule(ctx, "docker") {
		t.Error("module absent from the entry must be denied even if the single-context list has it")
	}
}

func TestRequireModule_Returns403WhenDisabled(t *testing.T) {
	resetModules(t)
	SetSingleContextModules([]string{"patching"})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	rec := httptest.NewRecorder()
	RequireModule("ssh_terminal")(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("disabled module: status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	RequireModule("patching")(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("enabled module: status = %d, want 204", rec.Code)
	}
}
