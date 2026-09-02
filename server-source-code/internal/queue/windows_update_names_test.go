package queue

import (
	"reflect"
	"testing"

	"github.com/PatchMon/PatchMon/server-source-code/internal/db"
)

func strp(s string) *string { return &s }

func wuaRows() []db.GetHostWindowsUpdatesRow {
	return []db.GetHostWindowsUpdatesRow{
		{
			PkgName: "2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)",
			WuaGuid: strp("0c3d3e9e-3b1a-4c1e-9d8a-2f0a7b6c5d4e"),
			WuaKb:   strp("KB5063878"),
		},
		{
			// wua_kb missing: the KB must still be found from the title.
			PkgName: "Security Intelligence Update for Microsoft Defender Antivirus (KB2267602)",
			WuaGuid: strp("11111111-2222-3333-4444-555555555555"),
		},
		{
			// Bare digits in wua_kb, as older agents stored it.
			PkgName: "2026-07 .NET 8 Update (KB5050001)",
			WuaGuid: strp("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
			WuaKb:   strp("5050001"),
		},
		{
			// No GUID: must never be used as a target.
			PkgName: "Broken Row (KB9999999)",
			WuaGuid: nil,
		},
	}
}

func TestMapWindowsUpdateNames_TitleAndKBResolveToGUID(t *testing.T) {
	t.Parallel()
	names := []string{
		"2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)",
		"kb2267602",
		"KB5050001",
		"Microsoft.VisualStudioCode",
		"11111111-2222-3333-4444-555555555555",
	}
	got, mapped := MapWindowsUpdateNames(names, wuaRows())
	want := []string{
		"0c3d3e9e-3b1a-4c1e-9d8a-2f0a7b6c5d4e",
		"11111111-2222-3333-4444-555555555555",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"Microsoft.VisualStudioCode",
		"11111111-2222-3333-4444-555555555555",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mapped names = %v, want %v", got, want)
	}
	if mapped != 3 {
		t.Errorf("mapped = %d, want 3", mapped)
	}
}

func TestMapWindowsUpdateNames_TitleMatchIsCaseAndSpaceInsensitive(t *testing.T) {
	t.Parallel()
	got, mapped := MapWindowsUpdateNames(
		[]string{"  2026-07 .net 8 update (kb5050001)  "},
		wuaRows(),
	)
	if mapped != 1 || got[0] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("got %v (mapped %d), want the .NET update GUID", got, mapped)
	}
}

func TestMapWindowsUpdateNames_UnknownNamesPassThroughUnchanged(t *testing.T) {
	t.Parallel()
	names := []string{"Mozilla.Firefox", "KB1234567", "Broken Row (KB9999999)", ""}
	got, mapped := MapWindowsUpdateNames(names, wuaRows())
	if !reflect.DeepEqual(got, names) {
		t.Errorf("got %v, want input unchanged %v", got, names)
	}
	if mapped != 0 {
		t.Errorf("mapped = %d, want 0", mapped)
	}
}

func TestMapWindowsUpdateNames_NoUpdatesIsANoop(t *testing.T) {
	t.Parallel()
	names := []string{"anything (KB5063878)"}
	got, mapped := MapWindowsUpdateNames(names, nil)
	if !reflect.DeepEqual(got, names) || mapped != 0 {
		t.Errorf("got %v (mapped %d), want input unchanged", got, mapped)
	}
}

func TestIsWUAGUID(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"0c3d3e9e-3b1a-4c1e-9d8a-2f0a7b6c5d4e": true,
		"0C3D3E9E-3B1A-4C1E-9D8A-2F0A7B6C5D4E": true,
		"0c3d3e9e3b1a4c1e9d8a2f0a7b6c5d4e":     false, // no dashes
		"0c3d3e9e-3b1a-4c1e-9d8a-2f0a7b6c5d4":  false, // too short
		"zzzzzzzz-3b1a-4c1e-9d8a-2f0a7b6c5d4e": false, // not hex
		"KB5063878":                            false,
	}
	for in, want := range cases {
		if got := isWUAGUID(in); got != want {
			t.Errorf("isWUAGUID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKBNumber(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"KB5063878":                       "5063878",
		"kb5063878":                       "5063878",
		"Cumulative Update (KB5063878)":   "5063878",
		"5063878":                         "5063878",
		"Microsoft.VisualStudioCode":      "",
		"KB12":                            "", // too short to be a KB
		"":                                "",
		"Something KBD 5063878 unrelated": "",
	}
	for in, want := range cases {
		if got := kbNumber(in); got != want {
			t.Errorf("kbNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsWindowsOS(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{"windows": true, "Windows 11": true, "Microsoft Windows Server 2022": true, "ubuntu": false, "": false} {
		if got := isWindowsOS(in); got != want {
			t.Errorf("isWindowsOS(%q) = %v, want %v", in, got, want)
		}
	}
}
