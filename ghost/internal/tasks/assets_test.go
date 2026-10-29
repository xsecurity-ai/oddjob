package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

// What a page pulls in is a fact about that page, and it was being
// thrown away with the DOM. Read from markup the crawler already had
// — no request is made to discover these.
func TestCrawlRecordsAssets(t *testing.T) {
	var cdnHits int
	cdn := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			cdnHits++
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = fmt.Fprint(w, "/* jquery 3.6.0 */ var $ = {};")
		}))
	defer cdn.Close()

	site := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, `<html><head><title>T</title>
<script src="%s/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<link rel="stylesheet" href="/css/site-2.1.0.css">
<script src="/static/app.a1b2c3.js"></script>
</head><body>hi</body></html>`, cdn.URL)
		}))
	defer site.Close()

	res := runKatana(context.Background(), map[string]any{
		"url": site.URL, "depth": 1,
	}, t.TempDir())
	if res.Status != "done" {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	var out struct {
		Assets []asset `json:"assets"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output shape: %v", err)
	}
	if len(out.Assets) < 3 {
		t.Fatalf("only %d assets: %+v", len(out.Assets), out.Assets)
	}

	byName := map[string]asset{}
	for _, a := range out.Assets {
		byName[a.Name] = a
	}
	if jq := byName["jquery"]; jq.Version != "3.6.0" {
		t.Errorf("jquery version %q, want 3.6.0", jq.Version)
	}
	if css := byName["site"]; css.Version != "2.1.0" || css.Kind != "stylesheet" {
		t.Errorf("stylesheet came back as %+v", css)
	}
	// A fingerprinted bundle: a name and NO version. Absent means
	// unknown. Guessing here would put a wrong version in front of
	// somebody who would act on it.
	if b, ok := byName["app.a1b2c3"]; !ok || b.Version != "" {
		t.Errorf("hashed bundle should carry no version, got %+v", b)
	}

	// `cdnHits` is deliberately not asserted to be zero here: both
	// servers are on 127.0.0.1, so katana reads them as the same
	// registrable domain and crawls the "CDN" as part of the site.
	// A real third-party host is a different domain and is out of
	// scope, so it is never requested. The property that matters --
	// that EXTRACTION costs no requests -- is proved directly in
	// TestAssetsFromIsPure, where there is no network to use.
	_ = cdnHits

	// ...and nothing is fetched unless asked.
	for _, a := range out.Assets {
		if a.SHA256 != "" || a.Body != "" {
			t.Errorf("%s was pulled back without fetch_assets", a.URL)
		}
	}
}

// With the flag, the bytes come back and are hashed.
func TestFetchAssetsPullsBundles(t *testing.T) {
	const js = "/* jquery v3.6.0 */ var $ = function () {};"
	var hits int
	cdn := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = fmt.Fprint(w, js)
		}))
	defer cdn.Close()

	in := []asset{{URL: cdn.URL + "/jquery-3.6.0.min.js", Kind: "script",
		Name: "jquery", Version: "3.6.0"}}
	got := fetchAssets(context.Background(), in,
		map[string]any{}, 1024*1024, 8*1024*1024)

	if len(got) != 1 {
		t.Fatalf("got %d assets", len(got))
	}
	a := got[0]
	if a.Status != 200 {
		t.Errorf("status %d", a.Status)
	}
	if a.Bytes != len(js) || a.Body != js {
		t.Errorf("body came back as %d bytes: %q", a.Bytes, a.Body)
	}
	if len(a.SHA256) != 64 {
		t.Errorf("sha256 is %q", a.SHA256)
	}
	if !strings.Contains(a.ContentType, "javascript") {
		t.Errorf("content type %q", a.ContentType)
	}
	if hits != 1 {
		t.Errorf("fetched %d times, want exactly one request per URL", hits)
	}
}

// A file over the cap gets NO hash and NO body. A hash of a prefix
// is not the file's hash, and anything matching a library against it
// would be matching a different file with confidence.
func TestOversizeAssetIsNotHashed(t *testing.T) {
	big := strings.Repeat("x", 4096)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, big)
		}))
	defer srv.Close()

	got := fetchAssets(context.Background(),
		[]asset{{URL: srv.URL + "/huge.js"}},
		map[string]any{}, 512, 8*1024*1024)
	a := got[0]
	if a.SHA256 != "" {
		t.Error("a truncated read was hashed — that hash is of a different file")
	}
	if a.Body != "" {
		t.Error("a truncated body was carried")
	}
	if a.FetchError == "" {
		t.Error("the size refusal was not reported, so it reads as a clean miss")
	}
}

// Extraction makes no requests, and cannot: it is handed a parsed
// document and has no client. This is the claim that "listing what a
// page pulls in is free" rests on, and it is worth proving somewhere
// a test cannot be fooled by two servers sharing a loopback address.
func TestAssetsFromIsPure(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`<html><head>
<script src="https://cdn.vendor.example/jquery-3.6.0.min.js"></script>
<link rel="stylesheet" href="/css/site-2.1.0.css">
<script src="data:text/javascript,void(0)"></script>
<script src="/static/app.a1b2c3.js"></script>
<iframe src="https://embed.other.example/x"></iframe>
</head></html>`))
	if err != nil {
		t.Fatal(err)
	}
	got := assetsFrom(doc, "https://site.acme.example/page")
	by := map[string]asset{}
	for _, a := range got {
		by[a.URL] = a
	}
	if len(got) != 4 {
		t.Fatalf("got %d assets: %+v", len(got), got)
	}
	// Relative references resolve against the page.
	if _, ok := by["https://site.acme.example/css/site-2.1.0.css"]; !ok {
		t.Error("a relative stylesheet was not resolved against the page")
	}
	// `data:` is not a dependency on anybody.
	for u := range by {
		if strings.HasPrefix(u, "data:") {
			t.Errorf("a data: URI was recorded as a dependency: %s", u)
		}
	}
	if a := by["https://cdn.vendor.example/jquery-3.6.0.min.js"]; a.Version != "3.6.0" {
		t.Errorf("cdn script version %q", a.Version)
	}
	if a := by["https://embed.other.example/x"]; a.Kind != "iframe" {
		t.Errorf("iframe kind %q", a.Kind)
	}
}

// Fetching an asset sends a request to whoever is serving it, and
// most asset URLs are on hosts the engagement does not have. The
// references are kept either way; only the fetch is scoped.
func TestAssetScopeDefaultsToFirstParty(t *testing.T) {
	if got := assetScope(map[string]any{}); got != "first-party" {
		t.Errorf("no argument should give the narrow scope, got %q", got)
	}
	// Default-is-safe: getting the value wrong costs a file nobody
	// fetched, never a request nobody authorised.
	for _, bad := range []any{"", "everything", "first-party", 1, nil, true} {
		if got := assetScope(map[string]any{"assets_scope": bad}); got == "all" {
			t.Errorf("%#v should not widen the scope, got %q", bad, got)
		}
	}
	// Case and surrounding space are forgiven; the word is not.
	for _, ok := range []string{"all", "ALL", "ALL ", " all "} {
		if got := assetScope(map[string]any{"assets_scope": ok}); got != "all" {
			t.Errorf("%q should widen the scope, got %q", ok, got)
		}
	}
}

func TestSamePartyAsset(t *testing.T) {
	cases := []struct {
		name, assetURL, page string
		want                 bool
	}{
		{"same host", "https://www.acme.example/app.js",
			"https://www.acme.example/", true},
		// Registrable domain, not hostname. Refusing this would
		// withhold exactly the bundles worth reading.
		{"sibling subdomain", "https://static.acme.example/app.js",
			"https://www.acme.example/", true},
		{"multi-label suffix", "https://cdn.acme.co.uk/app.js",
			"https://www.acme.co.uk/", true},
		{"a real CDN", "https://cdn.vendor.example/jquery.min.js",
			"https://www.acme.example/", false},
		// `acme.example.evil.test` is not `acme.example`, and a
		// suffix comparison would have said it was.
		{"suffix lookalike", "https://acme.example.evil.test/x.js",
			"https://www.acme.example/", false},
		{"same IP literal", "https://10.1.2.3/app.js",
			"https://10.1.2.3/index.html", true},
		{"different IP", "https://10.1.2.4/app.js",
			"https://10.1.2.3/index.html", false},
		// Could-not-determine must not collapse into yes.
		{"no page recorded", "https://www.acme.example/app.js", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := samePartyAsset(asset{URL: c.assetURL, Page: c.page})
			if got != c.want {
				t.Errorf("samePartyAsset(%q, page=%q) = %v, want %v",
					c.assetURL, c.page, got, c.want)
			}
		})
	}
}

// A second crawl of a site should not re-request every bundle it
// already stored. The saving is traffic at the client's servers and
// at whatever CDN fronts them: nothing here is a probe, but it is
// still the engagement's egress asking a stranger for a file it
// already has, on every run.
func TestAlreadyHeldSkipsTheFetch(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = fmt.Fprint(w, "var x = 1;")
		}))
	defer srv.Close()

	old := AssetsHeld
	defer func() { AssetsHeld = old }()

	stored := srv.URL + "/stored.js"
	fresh := srv.URL + "/fresh.js"
	var asked [][]string
	AssetsHeld = func(_ context.Context, urls []string) ([]string, error) {
		asked = append(asked, urls)
		return []string{stored}, nil
	}

	in := []asset{{URL: stored, Kind: "script"}, {URL: fresh, Kind: "script"}}
	held := alreadyHeld(context.Background(), in)
	if !held[stored] || held[fresh] {
		t.Fatalf("held set is %v", held)
	}
	if len(asked) != 1 || len(asked[0]) != 2 {
		t.Fatalf("asked %v, want one question carrying both urls", asked)
	}

	keep := []asset{}
	for _, a := range in {
		if !held[a.URL] {
			keep = append(keep, a)
		}
	}
	_ = fetchAssets(context.Background(), keep, map[string]any{},
		1024*1024, 8*1024*1024)
	if hits != 1 {
		t.Errorf("%d requests, want 1 — the stored bundle was asked for again", hits)
	}
}

// Not knowing has to mean fetching. A task run standalone has nobody
// to ask, and a missing bundle is a gap in the evidence while a
// repeated one is only traffic.
func TestAlreadyHeldIsEmptyWithoutAServer(t *testing.T) {
	old := AssetsHeld
	defer func() { AssetsHeld = old }()

	AssetsHeld = nil
	if got := alreadyHeld(context.Background(),
		[]asset{{URL: "https://a.example/x.js"}}); len(got) != 0 {
		t.Errorf("no hook should hold nothing, got %v", got)
	}

	// Same for a server that answers with an error: the crawl goes
	// ahead rather than stalling on a lookup that is an optimisation.
	AssetsHeld = func(context.Context, []string) ([]string, error) {
		return nil, fmt.Errorf("server unreachable")
	}
	if got := alreadyHeld(context.Background(),
		[]asset{{URL: "https://a.example/x.js"}}); len(got) != 0 {
		t.Errorf("a failed question should hold nothing, got %v", got)
	}
}

// The question is chunked, because the server caps it. A crawl that
// found 5,000 bundles must still get an answer rather than a 422.
func TestAlreadyHeldChunksBigCrawls(t *testing.T) {
	old := AssetsHeld
	defer func() { AssetsHeld = old }()

	var sizes []int
	AssetsHeld = func(_ context.Context, urls []string) ([]string, error) {
		sizes = append(sizes, len(urls))
		return urls[:1], nil
	}
	in := make([]asset, 0, heldChunk+5)
	for i := 0; i < heldChunk+5; i++ {
		in = append(in, asset{URL: fmt.Sprintf("https://a.example/%d.js", i)})
	}
	got := alreadyHeld(context.Background(), in)
	if len(sizes) != 2 || sizes[0] != heldChunk || sizes[1] != 5 {
		t.Fatalf("chunk sizes %v, want [%d 5]", sizes, heldChunk)
	}
	if len(got) != 2 {
		t.Errorf("both chunks' answers should be kept, got %v", got)
	}
}

// One URL on four hundred pages is one question, not four hundred.
func TestAlreadyHeldAsksOncePerURL(t *testing.T) {
	old := AssetsHeld
	defer func() { AssetsHeld = old }()

	var asked []string
	AssetsHeld = func(_ context.Context, urls []string) ([]string, error) {
		asked = urls
		return nil, nil
	}
	u := "https://a.example/jquery.js"
	alreadyHeld(context.Background(),
		[]asset{{URL: u, Page: "/a"}, {URL: u, Page: "/b"}, {URL: u, Page: "/c"}})
	if len(asked) != 1 {
		t.Errorf("asked %v, want the url once", asked)
	}
}
