package distmeta

import (
	"bytes"
	"encoding/xml"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

const v210ReleaseDate = "2026-06-01"

// repoRoot mirrors workflowpolicy/helpers_test.go pattern verbatim.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, ".github", "workflows")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("could not find repository root from test working directory")
		}
		current = parent
	}
}

func mustReadFile(t *testing.T, relPath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return data
}

func TestActiveReleaseMetadataVersions(t *testing.T) {
	const want = "2.10"

	t.Run("root_VERSION", func(t *testing.T) {
		got := strings.TrimSpace(string(mustReadFile(t, "VERSION")))
		if got != want {
			t.Fatalf("VERSION = %q, want %q", got, want)
		}
	})

	t.Run("fyne_details_version", func(t *testing.T) {
		var app struct {
			Details struct {
				Version string
			}
		}
		if err := toml.Unmarshal(mustReadFile(t, "src/FyneApp.toml"), &app); err != nil {
			t.Fatalf("parse FyneApp.toml: %v", err)
		}
		if app.Details.Version != want {
			t.Fatalf("FyneApp.toml Details.Version = %q, want %q", app.Details.Version, want)
		}
	})

	t.Run("snap_version", func(t *testing.T) {
		var snap struct {
			Version string `yaml:"version"`
		}
		if err := yaml.Unmarshal(mustReadFile(t, "dist/snapcraft/snapcraft.yaml"), &snap); err != nil {
			t.Fatalf("parse snapcraft.yaml: %v", err)
		}
		if snap.Version != want {
			t.Fatalf("snapcraft.yaml version = %q, want %q", snap.Version, want)
		}
	})

	t.Run("windows_versioninfo", func(t *testing.T) {
		text := string(mustReadFile(t, "dist/windows/versioninfo.rc"))
		required := []struct {
			name string
			re   *regexp.Regexp
		}{
			{name: "fileversion_numeric", re: regexp.MustCompile(`(?m)^FILEVERSION\s+2,10,0,0\r?$`)},
			{name: "productversion_numeric", re: regexp.MustCompile(`(?m)^PRODUCTVERSION\s+2,10,0,0\r?$`)},
			{name: "fileversion_string", re: regexp.MustCompile(`(?m)^\s*VALUE\s+"FileVersion",\s+"2\.10"\r?$`)},
		}
		for _, req := range required {
			t.Run(req.name, func(t *testing.T) {
				if !req.re.MatchString(text) {
					t.Fatalf("versioninfo.rc missing %s pattern %q", req.name, req.re.String())
				}
			})
		}
	})
}

func TestOldVersionLiteralsAreAllowlisted(t *testing.T) {
	var unexpected []string
	for _, relPath := range gitTrackedFiles(t) {
		data := mustReadFile(t, relPath)
		if !containsOldVersionLiteral(data) {
			continue
		}
		category, ok := oldVersionLiteralCategory(relPath)
		if !ok {
			unexpected = append(unexpected, relPath)
			continue
		}
		if category == "" {
			t.Fatalf("old-version allowlist category for %s is empty", relPath)
		}
	}
	if len(unexpected) > 0 {
		t.Fatalf("unallowlisted old-version literals in active repository files:\n%s", strings.Join(unexpected, "\n"))
	}
}

func TestChangelogV210ReleaseNotesContract(t *testing.T) {
	text := string(mustReadFile(t, "Changelog.md"))
	if !strings.HasPrefix(text, "# v2.10\n") {
		t.Fatalf("Changelog.md must begin with top-level # v2.10 entry")
	}

	v210Headings := regexp.MustCompile(`(?m)^# v2\.10\r?$`).FindAllStringIndex(text, -1)
	if len(v210Headings) != 1 {
		t.Fatalf("Changelog.md v2.10 top-level heading count = %d, want 1", len(v210Headings))
	}
	idx210 := v210Headings[0][0]
	idx209 := strings.Index(text, "# v2.09")
	if idx209 == -1 {
		t.Fatal("Changelog.md missing historical # v2.09 entry")
	}
	if idx210 >= idx209 {
		t.Fatalf("Changelog.md # v2.10 entry must appear before # v2.09")
	}
	if !strings.Contains(text, "# v2.08") {
		t.Fatal("Changelog.md missing historical # v2.08 entry")
	}

	section := changelogSection(t, text, "# v2.10")
	assertReleaseTextContains(t, "Changelog.md v2.10", section, []string{
		"Safer output cleanup",
		"Hardened archive extraction",
		"GUI race fixes",
		"Clearer damaged-header errors",
		"CLI and WASM notes",
		"Compatibility checks",
	})
	assertReleaseTextAvoids(t, "Changelog.md v2.10", section, forbiddenV210ReleasePhrases())
}

func changelogSection(t *testing.T, text, heading string) string {
	t.Helper()
	start := strings.Index(text, heading)
	if start == -1 {
		t.Fatalf("missing changelog heading %q", heading)
	}
	rest := text[start+len(heading):]
	nextHeading := regexp.MustCompile(`(?m)^# `).FindStringIndex(rest)
	if nextHeading == nil {
		return rest
	}
	return rest[:nextHeading[0]]
}

func assertReleaseTextContains(t *testing.T, label, text string, phrases []string) {
	t.Helper()
	lowerText := strings.ToLower(text)
	for _, phrase := range phrases {
		if !strings.Contains(lowerText, strings.ToLower(phrase)) {
			t.Errorf("%s missing required release-note phrase %q", label, phrase)
		}
	}
}

func assertReleaseTextAvoids(t *testing.T, label, text string, phrases []string) {
	t.Helper()
	lowerText := strings.ToLower(text)
	for _, phrase := range phrases {
		if strings.Contains(lowerText, strings.ToLower(phrase)) {
			t.Errorf("%s contains forbidden release-note phrase %q", label, phrase)
		}
	}
}

func forbiddenV210ReleasePhrases() []string {
	return []string{
		"new encryption format",
		"new encrypted format",
		"new file format",
		"new cryptographic primitive",
		"new crypto primitive",
		"expanded wasm feature set",
		"expanded wasm support",
		"new wasm features",
	}
}

func gitTrackedFiles(t *testing.T) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", repoRoot(t), "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	parts := bytes.Split(out, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		files = append(files, string(part))
	}
	return files
}

func containsOldVersionLiteral(data []byte) bool {
	for _, literal := range oldVersionLiterals {
		if bytes.Contains(data, []byte(literal)) {
			return true
		}
	}
	return false
}

var oldVersionLiterals = []string{"2.09", "v2.09", "2.08", "v2.08"}

func oldVersionLiteralCategory(relPath string) (string, bool) {
	switch {
	case relPath == "Changelog.md":
		return "historical changelog/release history", true
	case relPath == "dist/linux/io.github.picocrypt_ng.Picocrypt-NG.metainfo.xml":
		return "historical changelog/release history", true
	case relPath == "CLI.md":
		return "legacy snapshot", true
	case strings.HasPrefix(relPath, "src/testdata/golden/"):
		return "compatibility fixture", true
	case relPath == "src/internal/volume/golden_test.go":
		return "compatibility fixture", true
	case relPath == "src/internal/distmeta/distmeta_test.go":
		return "old-version test input", true
	case relPath == "src/cmd/picocrypt/version_test.go":
		return "old-version test input", true
	case relPath == "src/internal/cli/version_test.go":
		return "old-version test input", true
	case relPath == "src/internal/header/format_test.go":
		return "old-version test input", true
	case relPath == "src/internal/header/reader_test.go":
		return "old-version test input", true
	case relPath == "src/internal/ui/drop_test.go":
		return "old-version test input", true
	case relPath == "src/internal/ui/fyne_test_helpers_test.go":
		return "old-version test input", true
	case relPath == "src/internal/ui/preview_test.go":
		return "old-version test input", true
	case relPath == "src/internal/header/format.go", relPath == "src/internal/header/reader.go":
		return "old-version test input", true
	case relPath == "dist/windows/installer.nsi":
		return "legacy snapshot", true
	default:
		return "", false
	}
}

type mimeInfo struct {
	XMLName  xml.Name `xml:"http://www.freedesktop.org/standards/shared-mime-info mime-info"`
	MimeType []struct {
		Type    string `xml:"type,attr"`
		Comment []struct {
			Lang string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
			Text string `xml:",chardata"`
		} `xml:"comment"`
		Acronym         string `xml:"acronym"`
		ExpandedAcronym string `xml:"expanded-acronym"`
		Icon            struct {
			Name string `xml:"name,attr"`
		} `xml:"icon"`
		SubClassOf struct {
			Type string `xml:"type,attr"`
		} `xml:"sub-class-of"`
		Glob []struct {
			Pattern string `xml:"pattern,attr"`
		} `xml:"glob"`
	} `xml:"mime-type"`
}

func TestPCVMimeXMLContract(t *testing.T) {
	data := mustReadFile(t, "dist/mime/application-x-pcv.xml")
	var doc mimeInfo
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal mime xml: %v", err)
	}
	if len(doc.MimeType) != 1 {
		t.Fatalf("mime-type count = %d, want 1", len(doc.MimeType))
	}
	mt := doc.MimeType[0]
	if mt.Type != "application/x-pcv" {
		t.Errorf("type = %q, want %q", mt.Type, "application/x-pcv")
	}
	if len(mt.Glob) != 1 || mt.Glob[0].Pattern != "*.pcv" {
		t.Errorf("glob = %+v, want single *.pcv", mt.Glob)
	}
	if mt.Icon.Name != "application-x-pcv" {
		t.Errorf("icon name = %q, want %q", mt.Icon.Name, "application-x-pcv")
	}
	if mt.SubClassOf.Type != "application/octet-stream" {
		t.Errorf("sub-class-of = %q, want %q", mt.SubClassOf.Type, "application/octet-stream")
	}
	if mt.Acronym != "PCV" {
		t.Errorf("acronym = %q, want PCV", mt.Acronym)
	}
	if mt.ExpandedAcronym != "Picocrypt Volume" {
		t.Errorf("expanded-acronym = %q, want Picocrypt Volume", mt.ExpandedAcronym)
	}
	foundDefault, foundRu := false, false
	for _, c := range mt.Comment {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Lang == "" {
			foundDefault = true
		}
		if c.Lang == "ru" {
			foundRu = true
		}
	}
	if !foundDefault {
		t.Error("missing default-language comment")
	}
	if !foundRu {
		t.Error("missing xml:lang=ru comment")
	}
}

func TestPCVIconRenditions(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{name: "16", size: 16},
		{name: "32", size: 32},
		{name: "48", size: 48},
		{name: "64", size: 64},
		{name: "128", size: 128},
		{name: "256", size: 256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(repoRoot(t), "images", "pcv-icon-"+tc.name+".png")
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open %s: %v", path, err)
			}
			defer f.Close()
			img, err := png.Decode(f)
			if err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			b := img.Bounds()
			if b.Max.X != tc.size || b.Max.Y != tc.size {
				t.Fatalf("dimensions = %dx%d, want %dx%d", b.Max.X, b.Max.Y, tc.size, tc.size)
			}
		})
	}
}

func TestPCVMasterSVGExists(t *testing.T) {
	data := mustReadFile(t, "images/pcv-icon.svg")
	if !strings.Contains(string(data), `viewBox="0 0 256 256"`) {
		t.Errorf("pcv-icon.svg missing viewBox=\"0 0 256 256\"")
	}
	if !strings.Contains(string(data), `xmlns="http://www.w3.org/2000/svg"`) {
		t.Errorf("pcv-icon.svg missing svg namespace")
	}
}

func TestDesktopEntryContract(t *testing.T) {
	data := mustReadFile(t, "dist/linux/io.github.picocrypt_ng.Picocrypt-NG.desktop")
	text := string(data)

	requiredLines := []struct {
		name string
		line string
	}{
		{name: "header", line: "[Desktop Entry]"},
		{name: "type", line: "Type=Application"},
		{name: "mimetype", line: "MimeType=application/x-pcv;"},
		{name: "icon", line: "Icon=io.github.picocrypt_ng.Picocrypt-NG"},
	}
	for _, tc := range requiredLines {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(text, tc.line) {
				t.Errorf("desktop file missing required line: %q", tc.line)
			}
		})
	}

	// Exact anchored Exec= match (REVIEWS MEDIUM #2): only `Exec=picocrypt-ng-gui %f` accepted.
	// Loose `(?m)^Exec=.*%f\b` would have passed `Exec=wrong-binary %f`.
	// `\r?$` tolerates CRLF if a Windows checkout ignored .gitattributes.
	execRe := regexp.MustCompile(`(?m)^Exec=picocrypt-ng-gui %f\r?$`)
	if !execRe.MatchString(text) {
		t.Errorf("desktop file Exec= line must be exactly %q; want regex match for %q", "Exec=picocrypt-ng-gui %f", execRe.String())
	}

	// Negative field-code assertions (REVIEWS MEDIUM #2): Desktop Entry Spec §3.1 allows exactly one
	// of %f/%F/%u/%U; we require %f, so the others must be absent.
	forbiddenFieldCodes := []string{"%F", "%u", "%U"}
	for _, fc := range forbiddenFieldCodes {
		t.Run("forbidden_"+fc, func(t *testing.T) {
			if strings.Contains(text, fc) {
				t.Errorf("desktop file contains forbidden field code %q; only %%f is allowed per Desktop Entry Spec §3.1", fc)
			}
		})
	}

	if strings.Contains(text, "Encoding=") {
		t.Errorf("desktop file contains deprecated Encoding= key; remove per Desktop Entry Spec 1.4")
	}
}

func TestMetainfoContract(t *testing.T) {
	data := mustReadFile(t, "dist/linux/io.github.picocrypt_ng.Picocrypt-NG.metainfo.xml")

	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatalf("metainfo not well-formed XML: %v", err)
	}

	text := string(data)
	if !strings.Contains(text, "<mediatype>application/x-pcv</mediatype>") {
		t.Errorf("metainfo missing <mediatype>application/x-pcv</mediatype>")
	}
	if strings.Contains(text, "<mimetypes>") {
		t.Errorf("metainfo contains deprecated <mimetypes> tag; use <provides><mediatype> form per AppStream 1.0 spec")
	}
}

type appstreamMetainfo struct {
	Releases []appstreamRelease `xml:"releases>release"`
}

type appstreamRelease struct {
	Version     string                      `xml:"version,attr"`
	Date        string                      `xml:"date,attr"`
	URLs        []appstreamURL              `xml:"url"`
	Description appstreamReleaseDescription `xml:"description"`
}

type appstreamURL struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

type appstreamReleaseDescription struct {
	Items []string `xml:"ul>li"`
}

func TestMetainfoV210ReleaseHistory(t *testing.T) {
	data := mustReadFile(t, "dist/linux/io.github.picocrypt_ng.Picocrypt-NG.metainfo.xml")
	var doc appstreamMetainfo
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal metainfo release history: %v", err)
	}
	if len(doc.Releases) == 0 {
		t.Fatal("metainfo contains no release history")
	}

	current := doc.Releases[0]
	if current.Version != "2.10" {
		t.Fatalf("current metainfo release version = %q, want 2.10", current.Version)
	}
	if current.Date != v210ReleaseDate {
		t.Fatalf("current metainfo release date = %q, want %q", current.Date, v210ReleaseDate)
	}
	detailsURL := appstreamDetailsURL(current)
	if !strings.HasSuffix(detailsURL, "Changelog.md#v210") {
		t.Fatalf("current metainfo details URL = %q, want suffix Changelog.md#v210", detailsURL)
	}

	description := strings.Join(current.Description.Items, "\n")
	assertReleaseTextContains(t, "metainfo v2.10", description, []string{
		"Safer temporary output cleanup",
		"Hardened archive extraction",
		"GUI race fixes",
		"Clearer diagnostics",
		"CLI kept-output exit code",
		"Compatibility checks",
	})
	assertReleaseTextAvoids(t, "metainfo v2.10", description, forbiddenV210ReleasePhrases())

	versions := map[string]bool{}
	for _, release := range doc.Releases {
		versions[release.Version] = true
	}
	for _, want := range []string{"2.09", "2.08"} {
		if !versions[want] {
			t.Errorf("metainfo release history missing historical version %s", want)
		}
	}
}

func appstreamDetailsURL(release appstreamRelease) string {
	for _, url := range release.URLs {
		if url.Type == "details" {
			return strings.TrimSpace(url.Text)
		}
	}
	return ""
}

func TestSnapDesktopMimeType(t *testing.T) {
	data := mustReadFile(t, "dist/snapcraft/snap/gui/picocrypt-ng.desktop")
	text := string(data)

	if !strings.Contains(text, "MimeType=application/x-pcv;") {
		t.Errorf("snap desktop file missing MimeType=application/x-pcv;")
	}

	// Exact anchored Exec= match (REVIEWS MEDIUM #2): snap app name is `picocrypt-ng` per Q3 Option A,
	// NOT `picocrypt-ng-gui` (the .deb binary name). Loose regex would mask Option A drift.
	// `\r?$` tolerates CRLF if a Windows checkout ignored .gitattributes.
	execRe := regexp.MustCompile(`(?m)^Exec=picocrypt-ng %f\r?$`)
	if !execRe.MatchString(text) {
		t.Errorf("snap desktop file Exec= line must be exactly %q; want regex match for %q", "Exec=picocrypt-ng %f", execRe.String())
	}

	// Negative field-code assertions (REVIEWS MEDIUM #2): snap desktop must use %f only.
	forbiddenFieldCodes := []string{"%F", "%u", "%U"}
	for _, fc := range forbiddenFieldCodes {
		t.Run("forbidden_"+fc, func(t *testing.T) {
			if strings.Contains(text, fc) {
				t.Errorf("snap desktop file contains forbidden field code %q; only %%f is allowed per Desktop Entry Spec §3.1", fc)
			}
		})
	}
}

// plistValue is a parsed plist value: string, bool, int, []plistValue, or plistDict.
type plistValue struct {
	Kind  string                // "string"|"true"|"false"|"integer"|"real"|"array"|"dict"
	Str   string                // for string/integer/real (raw text)
	Array []plistValue          // for array
	Dict  map[string]plistValue // for dict
}

// decodePlist parses an entire <plist><dict>...</dict></plist> document.
// The plist DTD allows array, dict, string, integer, true, false, real, data, date —
// for our Info.plist only the first six are needed.
func decodePlist(t *testing.T, data []byte) map[string]plistValue {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist: scanning for top-level dict: %v", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "dict" {
			return parseDict(t, dec)
		}
	}
}

// parseDict consumes a <dict>...</dict> starting after the <dict> StartElement,
// returning the parsed key->value map. Keys and values alternate as siblings.
func parseDict(t *testing.T, dec *xml.Decoder) map[string]plistValue {
	t.Helper()
	out := map[string]plistValue{}
	var pendingKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist dict: %v", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			switch e.Name.Local {
			case "key":
				var s string
				if err := dec.DecodeElement(&s, &e); err != nil {
					t.Fatalf("plist key: %v", err)
				}
				pendingKey = s
			default:
				if pendingKey == "" {
					t.Fatalf("plist: value <%s> with no preceding key", e.Name.Local)
				}
				out[pendingKey] = parseValue(t, dec, e)
				pendingKey = ""
			}
		case xml.EndElement:
			if e.Name.Local == "dict" {
				return out
			}
		}
	}
}

func parseValue(t *testing.T, dec *xml.Decoder, start xml.StartElement) plistValue {
	t.Helper()
	switch start.Name.Local {
	case "string", "integer", "real":
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			t.Fatalf("plist %s: %v", start.Name.Local, err)
		}
		return plistValue{Kind: start.Name.Local, Str: s}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			t.Fatalf("plist %s: %v", start.Name.Local, err)
		}
		return plistValue{Kind: start.Name.Local}
	case "array":
		var arr []plistValue
		for {
			tok, err := dec.Token()
			if err != nil {
				t.Fatalf("plist array: %v", err)
			}
			switch e := tok.(type) {
			case xml.StartElement:
				arr = append(arr, parseValue(t, dec, e))
			case xml.EndElement:
				if e.Name.Local == "array" {
					return plistValue{Kind: "array", Array: arr}
				}
			}
		}
	case "dict":
		return plistValue{Kind: "dict", Dict: parseDict(t, dec)}
	}
	t.Fatalf("plist: unsupported value tag <%s>", start.Name.Local)
	return plistValue{}
}

func TestMacOSInfoPlist(t *testing.T) {
	data := mustReadFile(t, "dist/macos/Info.plist")

	// Syntactic XML well-formedness (plutil -lint validates DTD on macOS;
	// here we validate XML well-formedness as a fast cross-platform check).
	var probe struct{ XMLName xml.Name }
	if err := xml.Unmarshal(data, &probe); err != nil {
		t.Fatalf("Info.plist not well-formed XML: %v", err)
	}

	root := decodePlist(t, data)

	// --- Identity assertions (D-14, D-15) ---
	if got := root["CFBundleIdentifier"].Str; got != "io.github.picocryptng.PicocryptNG" {
		t.Errorf("CFBundleIdentifier = %q, want io.github.picocryptng.PicocryptNG", got)
	}
	if got := root["CFBundleExecutable"].Str; got != "Picocrypt-NG" {
		t.Errorf("CFBundleExecutable = %q, want Picocrypt-NG", got)
	}
	if got := root["CFBundlePackageType"].Str; got != "APPL" {
		t.Errorf("CFBundlePackageType = %q, want APPL", got)
	}
	if got := root["LSMinimumSystemVersion"].Str; got != "15.0" {
		t.Errorf("LSMinimumSystemVersion = %q, want 15.0", got)
	}
	if root["NSHighResolutionCapable"].Kind != "true" {
		t.Errorf("NSHighResolutionCapable should be <true/>")
	}

	// --- CFBundleDocumentTypes (FA-MAC-01; D-07, D-08, D-09) ---
	docs := root["CFBundleDocumentTypes"]
	if docs.Kind != "array" || len(docs.Array) == 0 {
		t.Fatalf("CFBundleDocumentTypes missing or not array")
	}
	entry := docs.Array[0].Dict
	if entry["CFBundleTypeRole"].Str != "Editor" {
		t.Errorf("CFBundleTypeRole = %q, want Editor", entry["CFBundleTypeRole"].Str)
	}
	if entry["LSHandlerRank"].Str != "Owner" {
		t.Errorf("LSHandlerRank = %q, want Owner", entry["LSHandlerRank"].Str)
	}
	itemTypes := entry["LSItemContentTypes"].Array
	foundUTI := false
	for _, v := range itemTypes {
		if v.Str == "io.github.picocryptng.pcv" {
			foundUTI = true
			break
		}
	}
	if !foundUTI {
		t.Errorf("LSItemContentTypes missing io.github.picocryptng.pcv; got %+v", itemTypes)
	}

	// --- UTExportedTypeDeclarations (FA-MAC-02; D-04, D-05, D-06) ---
	utis := root["UTExportedTypeDeclarations"]
	if utis.Kind != "array" || len(utis.Array) == 0 {
		t.Fatalf("UTExportedTypeDeclarations missing or not array")
	}
	uti := utis.Array[0].Dict
	if uti["UTTypeIdentifier"].Str != "io.github.picocryptng.pcv" {
		t.Errorf("UTTypeIdentifier = %q, want io.github.picocryptng.pcv", uti["UTTypeIdentifier"].Str)
	}
	conformsTo := uti["UTTypeConformsTo"].Array
	if len(conformsTo) != 1 || conformsTo[0].Str != "public.data" {
		t.Errorf("UTTypeConformsTo = %+v, want [public.data] only (D-05: NOT public.archive)", conformsTo)
	}
	tagSpec := uti["UTTypeTagSpecification"].Dict
	exts := tagSpec["public.filename-extension"].Array
	gotExt := false
	for _, v := range exts {
		if v.Str == "pcv" {
			gotExt = true
			break
		}
	}
	if !gotExt {
		t.Errorf("UTTypeTagSpecification public.filename-extension missing pcv; got %+v", exts)
	}
	mimes := tagSpec["public.mime-type"].Array
	gotMime := false
	for _, v := range mimes {
		if v.Str == "application/x-pcv" {
			gotMime = true
			break
		}
	}
	if !gotMime {
		t.Errorf("UTTypeTagSpecification public.mime-type missing application/x-pcv; got %+v", mimes)
	}

	// --- Negative assertion: ensure stale hyphenated bundle ID is gone (D-14 fix) ---
	if strings.Contains(string(data), "io.github.picocrypt-ng") {
		t.Errorf("Info.plist still contains pre-Phase-3 stale ID 'io.github.picocrypt-ng' (must be picocryptng — no hyphen)")
	}
}

// TestWindowsNSISScript validates the canonical NSIS installer script in
// dist/windows/installer.nsi. Mirrors Phase 2/3 contract test patterns
// (TestSnapDesktopMimeType + TestMacOSInfoPlist) — regex-based assertions
// since NSIS has no formal Go grammar (D-32). makensis itself is not invoked
// here; CI compiles the script on a Windows host (D-33, build-windows.yml
// Phase 4 step).
func TestWindowsNSISScript(t *testing.T) {
	data := mustReadFile(t, "dist/windows/installer.nsi")
	text := string(data)

	// --- Positive assertions: required canonical strings (table-driven) ---
	requiredLiterals := []struct {
		name string
		line string
	}{
		{name: "progid", line: "PicocryptNG.pcv"},                           // D-20
		{name: "content_type", line: `"application/x-pcv"`},                 // D-21 + Pattern S-1
		{name: "registered_apps", line: `Software\RegisteredApplications`},  // D-22
		{name: "capabilities_assoc", line: `Capabilities\FileAssociations`}, // D-22
		{name: "version_guard", line: "!ifndef VERSION"},                    // D-03 + Pitfall 3
		{name: "uac", line: "RequestExecutionLevel admin"},                  // D-07
	}
	for _, tc := range requiredLiterals {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(text, tc.line) {
				t.Errorf("installer.nsi missing required literal: %q", tc.line)
			}
		})
	}

	// --- Positive assertions: regex patterns ---
	t.Run("shell_open_command_with_arg1", func(t *testing.T) {
		// D-21: shell\open\command writes "$INSTDIR\Picocrypt-NG.exe" "%1"
		re := regexp.MustCompile(`shell\\open\\command.*%1`)
		if !re.MatchString(text) {
			t.Errorf("installer.nsi missing shell\\open\\command with %%1 placeholder")
		}
	})

	t.Run("running_x64_guard", func(t *testing.T) {
		// D-09: ${IfNot} ${RunningX64} → Abort. Match RunningX64 anywhere in script
		// (covers ${IfNot} ${RunningX64}, ${If} ${RunningX64}, etc.)
		if !regexp.MustCompile(`\$\{(?:IfNot\s+)?RunningX64\}`).MatchString(text) {
			t.Errorf("installer.nsi missing ${RunningX64} 64-bit guard (D-09)")
		}
	})

	t.Run("license_path_filedir_anchored", func(t *testing.T) {
		// D-11 + Pitfall 5: license path MUST be ${__FILEDIR__}\..\..\LICENSE
		// (NOT $%CD% which is brittle across CWDs).
		re := regexp.MustCompile(`MUI_PAGE_LICENSE\s+"\$\{__FILEDIR__\}\\\.\.\\\.\.\\LICENSE"`)
		if !re.MatchString(text) {
			t.Errorf("installer.nsi MUI_PAGE_LICENSE must reference ${__FILEDIR__}\\..\\..\\LICENSE (Pitfall 5)")
		}
	})

	t.Run("shchangenotify_at_least_twice", func(t *testing.T) {
		// D-25 + D-26: SHChangeNotify must appear in BOTH install Section and Uninstall Section.
		matches := regexp.MustCompile(`SHChangeNotify`).FindAllString(text, -1)
		if len(matches) < 2 {
			t.Errorf("installer.nsi must call SHChangeNotify at least twice (install + uninstall); found %d", len(matches))
		}
	})

	t.Run("setregview_64_install_and_uninstall", func(t *testing.T) {
		// Pitfall 4: SetRegView 64 MUST appear in BOTH .onInit and un.onInit
		// (without it, NSIS x86 installer writes to WOW6432Node, hidden from Default Apps UI).
		matches := regexp.MustCompile(`SetRegView 64`).FindAllString(text, -1)
		if len(matches) < 2 {
			t.Errorf("installer.nsi must call SetRegView 64 at least twice (.onInit + un.onInit); found %d", len(matches))
		}
	})

	// --- Uninstaller block scoped assertions (D-27 hybrid cleanup) ---
	uninstallBlock := regexp.MustCompile(`(?ms)Section\s+"Uninstall".*?SectionEnd`).FindString(text)
	if uninstallBlock == "" {
		t.Fatalf("installer.nsi missing 'Section \"Uninstall\"' block — cannot validate D-27 cleanup")
	}
	t.Run("uninstall_deletes_progid", func(t *testing.T) {
		// Accept either the literal ProgID or the NSIS preprocessor reference ${PROGID}
		// (script !defines PROGID = "PicocryptNG.pcv"; DRY > literal repetition).
		if !regexp.MustCompile(`DeleteRegKey.*(PicocryptNG\.pcv|\$\{PROGID\})`).MatchString(uninstallBlock) {
			t.Errorf("Uninstall Section missing DeleteRegKey for PicocryptNG.pcv ProgID (D-27)")
		}
	})
	t.Run("uninstall_deletes_openwithprogids_value", func(t *testing.T) {
		if !regexp.MustCompile(`DeleteRegValue.*OpenWithProgids`).MatchString(uninstallBlock) {
			t.Errorf("Uninstall Section missing DeleteRegValue for OpenWithProgids entry (D-27)")
		}
	})
	t.Run("uninstall_shchangenotify", func(t *testing.T) {
		if !strings.Contains(uninstallBlock, "SHChangeNotify") {
			t.Errorf("Uninstall Section missing SHChangeNotify call (D-26)")
		}
	})

	// --- Negative assertions: anti-patterns that must NOT appear ---
	negatives := []struct {
		name   string
		needle string
		why    string
	}{
		{name: "no_wow6432node_literal", needle: "WOW6432Node", why: "SetRegView 64 must handle redirection (Pitfall 4); manual WOW6432 paths indicate missing SetRegView"},
		{name: "no_pct_cd_path", needle: "$%CD%", why: "$%CD% is brittle across CWDs; use ${__FILEDIR__} (Pitfall 5)"},
		{name: "no_hkcr_writeregstr", needle: `WriteRegStr HKCR`, why: "HKCR is a virtual merged view; write to HKLM\\Software\\Classes\\... per Microsoft Default Programs spec"},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(text, tc.needle) {
				t.Errorf("installer.nsi contains forbidden pattern %q: %s", tc.needle, tc.why)
			}
		})
	}

	// --- Negative: no Cyrillic / non-ASCII script chars (D-14, Pitfall 9) ---
	// English-only LangString + comments. Use bytes scan to avoid expensive regex on UTF.
	t.Run("no_cyrillic_chars", func(t *testing.T) {
		for i, r := range text {
			if r >= 0x0400 && r <= 0x04FF {
				t.Errorf("installer.nsi contains Cyrillic character %q at byte offset %d (D-14 English-only; Pitfall 9 -INPUTCHARSET)", r, i)
				return // stop at first match to avoid log spam
			}
		}
	})
}

// TestWindowsICO validates images/pcv-icon.ico — pre-rendered multi-resolution
// ICO committed to the repo (D-16, D-34). Mirrors TestPCVIconRenditions
// pattern but for binary ICO format (no png.Decode; raw byte assertions).
func TestWindowsICO(t *testing.T) {
	data := mustReadFile(t, "images/pcv-icon.ico")

	// D-34: file size > 1 KB (multi-resolution ICO with 6 entries minimum,
	// PNG inputs total 11042 bytes; expect ICO ~12-30 KB).
	if len(data) < 1024 {
		t.Errorf("pcv-icon.ico size = %d bytes, want > 1024", len(data))
	}

	// D-34: ICO magic bytes (ICONDIR header per Wikipedia ICO spec):
	//   bytes 0-1: 00 00  (reserved, must be 0)
	//   bytes 2-3: 01 00  (type=1, ICO; 02 00 = CUR)
	if len(data) < 4 || !bytes.Equal(data[:4], []byte{0x00, 0x00, 0x01, 0x00}) {
		got := []byte{}
		if len(data) >= 4 {
			got = data[:4]
		} else {
			got = data
		}
		t.Errorf("pcv-icon.ico magic bytes = % x, want 00 00 01 00", got)
	}

	// D-34: image count at bytes 4-5 (little-endian uint16); D-16 specifies 6 sizes
	// (16/32/48/64/128/256). Assert exactly 6 to catch accidental size omissions
	// in render-icons.sh changes.
	if len(data) >= 6 {
		count := uint16(data[4]) | uint16(data[5])<<8
		if count != 6 {
			t.Errorf("pcv-icon.ico image count = %d, want 6 (sizes 16/32/48/64/128/256 per D-16)", count)
		}
	} else {
		t.Errorf("pcv-icon.ico too short to contain ICONDIR header (%d bytes)", len(data))
	}
}
