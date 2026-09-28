package panel

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// TestAppCSSBuiltAndValid verifies that static/css/app.css is present, non-empty,
// and contains required CSS markers so the panel is never compiled unstyled.
func TestAppCSSBuiltAndValid(t *testing.T) {
	data, err := staticFiles.ReadFile("static/css/app.css")
	if err != nil {
		t.Fatalf("static/css/app.css missing from embedded staticFiles. Run 'make css' before running tests: %v", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		t.Fatalf("static/css/app.css is empty. Run 'make css' to generate CSS.")
	}

	content := string(data)
	requiredMarkers := []string{
		".btn",
		"--color-bg",
		"--color-primary",
	}

	for _, marker := range requiredMarkers {
		if !strings.Contains(content, marker) {
			t.Errorf("static/css/app.css missing expected marker %q; CSS may be corrupted or unbuilt", marker)
		}
	}
}

// TestStaticPagePartialsServed verifies that static pages and core assets are served via HTTP.
func TestStaticPagePartialsServed(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	requiredAssets := []string{
		"/static/pages/dashboard.html",
		"/static/pages/domains.html",
		"/static/pages/users.html",
		"/static/pages/blacklist.html",
		"/static/pages/request-logs.html",
		"/static/pages/usage.html",
		"/static/pages/settings.html",
		"/static/css/app.css",
		"/static/js/theme-init.js",
		"/static/js/app.js",
		"/css/app.css",
		"/js/theme-init.js",
		"/js/app.js",
	}

	for _, asset := range requiredAssets {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", asset, nil)
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for %s, got %d", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("expected non-empty body for %s", asset)
		}
	}

	// Also test custom path prefix (e.g. /admin)
	if err := srv.ApplyPathPrefix("/admin"); err != nil {
		t.Fatalf("failed to apply prefix: %v", err)
	}

	prefixAssets := []string{
		"/admin/css/app.css",
		"/admin/js/theme-init.js",
		"/admin/js/app.js",
		"/admin/static/css/app.css",
	}
	for _, asset := range prefixAssets {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", asset, nil)
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for custom prefix asset %s, got %d", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("expected non-empty body for custom prefix asset %s", asset)
		}
	}
}

// TestStaticIntegrity validates:
// (a) every local href/src in index.html resolves in the embedded FS
// (b) every local JS import resolves in embedded FS
// (c) no duplicate id attributes across index.html + pages/*.html
// (d) no external https?:// URLs in html/css files (no CDN/fonts/external scripts)
func TestStaticIntegrity(t *testing.T) {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		t.Fatalf("failed to sub static FS: %v", err)
	}

	// (a) Check index.html local references
	indexData, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		t.Fatalf("failed to read index.html: %v", err)
	}
	indexContent := string(indexData)

	refRe := regexp.MustCompile(`(?:href|src)=["']([^"':#]+)["']`)
	matches := refRe.FindAllStringSubmatch(indexContent, -1)
	for _, m := range matches {
		ref := m[1]
		if strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
			continue
		}
		ref = strings.TrimPrefix(ref, "./")
		ref = strings.TrimPrefix(ref, "/")
		if _, err := fs.Stat(staticFS, ref); err != nil {
			t.Errorf("index.html references non-existent file %q: %v", ref, err)
		}
	}

	// (b) Check JS imports resolve
	err = fs.WalkDir(staticFS, "js", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".js") {
			return err
		}
		jsData, err := fs.ReadFile(staticFS, path)
		if err != nil {
			return err
		}
		importRe := regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]|import\(['"]([^'"]+)['"]\)`)
		importMatches := importRe.FindAllStringSubmatch(string(jsData), -1)
		dir := filepath.Dir(path)
		for _, im := range importMatches {
			target := im[1]
			if target == "" {
				target = im[2]
			}
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				t.Errorf("%s contains external import %q", path, target)
				continue
			}
			if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
				resolved := filepath.Clean(filepath.Join(dir, target))
				if _, err := fs.Stat(staticFS, resolved); err != nil {
					t.Errorf("%s imports %q which resolves to missing file %q: %v", path, target, resolved, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking js dir: %v", err)
	}

	// (c) Check duplicate IDs across index.html and pages/*.html
	seenIDs := make(map[string]string)
	idRe := regexp.MustCompile(`\bid=["']([^"']+)["']`)

	checkIDs := func(file string, content string) {
		idMatches := idRe.FindAllStringSubmatch(content, -1)
		for _, m := range idMatches {
			id := m[1]
			if prevFile, exists := seenIDs[id]; exists {
				t.Errorf("duplicate id %q in %s (previously seen in %s)", id, file, prevFile)
			} else {
				seenIDs[id] = file
			}
		}
	}

	checkIDs("index.html", indexContent)

	pages, _ := fs.Glob(staticFS, "pages/*.html")
	for _, page := range pages {
		pData, err := fs.ReadFile(staticFS, page)
		if err == nil {
			checkIDs(page, string(pData))
		}
	}

	// (d) Ensure no external HTTP/HTTPS links in index.html, pages/*.html, or input.css
	extRe := regexp.MustCompile(`https?://`)
	if extRe.MatchString(indexContent) {
		t.Errorf("index.html contains external URL (no external runtime network requests allowed)")
	}
	for _, page := range pages {
		pData, err := fs.ReadFile(staticFS, page)
		if err == nil && extRe.MatchString(string(pData)) {
			t.Errorf("%s contains external URL", page)
		}
	}
	inputCSS, err := os.ReadFile("internal/panel/static/css/input.css")
	if err == nil && extRe.MatchString(string(inputCSS)) {
		t.Errorf("input.css contains external URL (e.g. font imports)")
	}
}
