package distmeta

import (
	"bytes"
	"encoding/xml"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
