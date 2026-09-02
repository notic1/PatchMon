package queue

import (
	"context"
	"regexp"
	"strings"

	"github.com/PatchMon/PatchMon/server-source-code/internal/db"
)

// kbPattern finds a Microsoft KB number anywhere in a package name, such as
// the "(KB5063878)" suffix the agent appends to Windows Update titles, or a
// bare "KB5063878" typed by an operator.
var kbPattern = regexp.MustCompile(`(?i)\bKB(\d{4,})\b`)

// MapWindowsUpdateNames replaces Windows Update display names in names with
// the WUA GUID the agent needs to install them.
//
// The UI sends package_names exactly as the agent reported them, which for a
// Windows Update is the title plus its KB number, for example "2026-08
// Cumulative Update for Windows 11 (KB5063878)". The agent only routes bare
// GUIDs to Windows Update (a "KB…" string is routed there too but WUA cannot
// search by it), so a title fell through to `winget upgrade --id` and failed
// as "non-fatal". A name that matches one of the host's known updates, by
// exact title or by KB number, becomes that update's GUID. Everything else,
// WinGet package IDs and GUIDs already, passes through unchanged and in the
// same position. The second result is how many names were rewritten.
func MapWindowsUpdateNames(names []string, updates []db.GetHostWindowsUpdatesRow) ([]string, int) {
	if len(names) == 0 || len(updates) == 0 {
		return names, 0
	}

	byTitle := make(map[string]string, len(updates))
	byKB := make(map[string]string, len(updates))
	for _, u := range updates {
		if u.WuaGuid == nil || *u.WuaGuid == "" {
			continue
		}
		guid := *u.WuaGuid
		if title := strings.ToLower(strings.TrimSpace(u.PkgName)); title != "" {
			if _, seen := byTitle[title]; !seen {
				byTitle[title] = guid
			}
		}
		if u.WuaKb != nil {
			if kb := kbNumber(*u.WuaKb); kb != "" {
				if _, seen := byKB[kb]; !seen {
					byKB[kb] = guid
				}
			}
		}
		// The title carries the KB as well; index it so a KB lookup works
		// even for rows where wua_kb was not populated.
		if kb := kbNumber(u.PkgName); kb != "" {
			if _, seen := byKB[kb]; !seen {
				byKB[kb] = guid
			}
		}
	}

	out := make([]string, len(names))
	mapped := 0
	for i, raw := range names {
		out[i] = raw
		name := strings.TrimSpace(raw)
		if name == "" || isWUAGUID(name) {
			continue
		}
		if guid, ok := byTitle[strings.ToLower(name)]; ok {
			out[i] = guid
			mapped++
			continue
		}
		if kb := kbNumber(name); kb != "" {
			if guid, ok := byKB[kb]; ok {
				out[i] = guid
				mapped++
			}
		}
	}
	return out, mapped
}

// kbNumber extracts the digits of a KB reference from s. Accepts "KB5063878",
// "kb5063878", a title containing "(KB5063878)", or bare digits as stored in
// wua_kb by some agent versions. Returns "" when there is none.
func kbNumber(s string) string {
	s = strings.TrimSpace(s)
	if m := kbPattern.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	if s != "" && strings.Trim(s, "0123456789") == "" {
		return s
	}
	return ""
}

// isWUAGUID reports whether s is already the 8-4-4-4-12 hex identifier the
// agent's Windows Update path searches by.
func isWUAGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// isWindowsOS matches the os_type values the Windows agent reports.
func isWindowsOS(osType string) bool {
	return strings.Contains(strings.ToLower(osType), "windows")
}

// resolveWindowsUpdateNames maps package names for a run_patch dispatch when
// the target host runs Windows. Any failure to look the host or its updates
// up leaves the names untouched: the run then behaves exactly as before this
// mapping existed, and the reason is logged.
func (h *RunPatchHandler) resolveWindowsUpdateNames(ctx context.Context, p RunPatchPayload, names []string) []string {
	if len(names) == 0 || h.hosts == nil || h.db == nil {
		return names
	}
	host, err := h.hosts.GetByApiID(ctx, p.ApiID)
	if err != nil || host == nil || !isWindowsOS(host.OSType) {
		return names
	}
	d := h.db.DB(ctx)
	if d == nil {
		return names
	}
	rows, err := d.Queries.GetHostWindowsUpdates(ctx, host.ID)
	if err != nil {
		h.log.Warn("run_patch: could not load Windows Update inventory, sending package names unmapped",
			"api_id", p.ApiID, "patch_run_id", p.PatchRunID, "error", err)
		return names
	}
	mapped, n := MapWindowsUpdateNames(names, rows)
	if n > 0 {
		h.log.Info("run_patch: resolved Windows Update names to WUA GUIDs",
			"api_id", p.ApiID, "patch_run_id", p.PatchRunID, "mapped", n, "total", len(names))
	}
	return mapped
}
