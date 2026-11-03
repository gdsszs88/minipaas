package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func testSupabaseRoute(appID, project string) ProxyRoute {
	return ProxyRoute{ID: "route_" + appID, AppID: appID, Name: "Supabase", ProxyType: "supabase", SupabaseProjectID: project, Enabled: true, PathPrefix: "/supabase/*", Upstream: "https://" + project + ".supabase.co", StripPrefix: true, UpstreamHost: project + ".supabase.co", Streaming: true, Sort: 10}
}

func TestRenderManagedCaddyOrdersProxyBeforeFallback(t *testing.T) {
	const appID = "app_123456"
	state := State{CaddyBaseConfigs: map[string]string{"server": ""}, SubscriptionRoutes: []SubscriptionRouting{{AppID: appID, SupabaseProjectID: "ltvyvkdntvgicumfzgjy", Enabled: true, Domains: []string{"dy.ip520.top"}, Upstream: jiedianMigrationUpstream, UpstreamHost: jiedianMigrationHost, AuthorizationURL: jiedianMigrationUpstream + "/functions/v1/subscription/domain-authorized"}}, Apps: []App{{ID: appID, Name: "jiedianshangcheng3.0", ServerID: "server", Port: 80, Domains: []Domain{{Host: "www.ip520.top"}}, ProxyRoutes: []ProxyRoute{testSupabaseRoute(appID, "ltvyvkdntvgicumfzgjy")}}}}
	config := renderManagedCaddy(state, "server")
	proxyAt := strings.Index(config, "handle_path /supabase/*")
	fallbackAt := strings.Index(config, "handle {\n    reverse_proxy mp-jiedianshangcheng3-0-123456")
	if proxyAt < 0 || fallbackAt < 0 || proxyAt >= fallbackAt {
		t.Fatalf("proxy route must precede app fallback:\n%s", config)
	}
	for _, expected := range []string{"header_up Host \"ltvyvkdntvgicumfzgjy.supabase.co\"", "flush_interval -1", "^/s/([0-9a-fA-F-]+)$", "domain-authorized"} {
		if !strings.Contains(config, expected) {
			t.Fatalf("missing %q in generated Caddyfile", expected)
		}
	}
}

func TestMultiAppSupabaseRoutesAreIsolated(t *testing.T) {
	const projectA = "aaaaaaaaaaaaaaaaaaaa"
	const projectB = "bbbbbbbbbbbbbbbbbbbb"
	state := State{CaddyBaseConfigs: map[string]string{"server": ""}, Apps: []App{
		{ID: "app-a", Name: "site-a", ServerID: "server", Port: 80, Domains: []Domain{{Host: "a.example.com"}}, ProxyRoutes: []ProxyRoute{testSupabaseRoute("app-a", projectA)}},
		{ID: "app-b", Name: "site-b", ServerID: "server", Port: 80, Domains: []Domain{{Host: "b.example.com"}}, ProxyRoutes: []ProxyRoute{testSupabaseRoute("app-b", projectB)}},
		{ID: "app-c", Name: "site-c", ServerID: "server", Port: 80, Domains: []Domain{{Host: "c.example.com"}}},
	}}
	config := renderManagedCaddy(state, "server")
	blockA := between(config, "# app:app-a", "# app:app-b")
	blockB := between(config, "# app:app-b", "# app:app-c")
	blockC := between(config, "# app:app-c", "# END MINIPAAS")
	if !strings.Contains(blockA, projectA) || strings.Contains(blockA, projectB) {
		t.Fatalf("app A route crossed projects:\n%s", blockA)
	}
	if !strings.Contains(blockB, projectB) || strings.Contains(blockB, projectA) {
		t.Fatalf("app B route crossed projects:\n%s", blockB)
	}
	if strings.Contains(blockC, "/supabase") || strings.Contains(blockC, ".supabase.co") {
		t.Fatalf("unconfigured app received a Supabase route:\n%s", blockC)
	}
	beforeB := blockB
	state.Apps[0].ProxyRoutes[0].PathPrefix = "/backend/*"
	afterB := between(renderManagedCaddy(state, "server"), "# app:app-b", "# app:app-c")
	if afterB != beforeB {
		t.Fatalf("updating app A changed app B block\nbefore:\n%s\nafter:\n%s", beforeB, afterB)
	}
}

func TestRoutingConflictsAndBindingAreRejected(t *testing.T) {
	state := State{Apps: []App{{ID: "app-a", Name: "A", Domains: []Domain{{Host: "a.example.com"}}}, {ID: "app-b", Name: "B", Domains: []Domain{{Host: "b.example.com"}}}}}
	duplicatePaths := []ProxyRoute{{AppID: "app-a", Name: "one", Enabled: true, PathPrefix: "/api/*"}, {AppID: "app-a", Name: "two", Enabled: true, PathPrefix: "/api/*"}}
	if err := validateRoutingConflicts(state, "app-a", duplicatePaths, nil); err == nil {
		t.Fatal("expected duplicate enabled paths to be rejected")
	}
	if err := validateAppDomainOwnership(state, "app-a", []string{"b.example.com"}); err == nil {
		t.Fatal("expected cross-app domain ownership conflict")
	}
	if _, err := normalizeProxyRoutes("app-a", []ProxyRoute{{AppID: "app-b", Name: "wrong"}}); err == nil {
		t.Fatal("expected mismatched appId to be rejected")
	}
}

func TestSupabaseProjectMustMatchUpstream(t *testing.T) {
	route := testSupabaseRoute("app-a", "ltvyvkdntvgicumfzgjy")
	route.SupabaseProjectID = "bbbbbbbbbbbbbbbbbbbb"
	if _, err := normalizeProxyRoutes("app-a", []ProxyRoute{route}); err == nil || !strings.Contains(err.Error(), "Project ID") {
		t.Fatalf("expected project mismatch, got %v", err)
	}
}

func TestProxySuggestionsOnlyUseCurrentAppVariables(t *testing.T) {
	box, err := OpenSecretBox(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(value string) string {
		ciphertext, encryptErr := box.Encrypt([]byte(value))
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return ciphertext
	}
	app := App{ID: "app-a", Domains: []Domain{{Host: "a.example.com"}}, Variables: []Variable{
		{Key: "VITE_SUPABASE_URL", EncryptedValue: encrypt("https://a.example.com/supabase")},
		{Key: "VITE_SUPABASE_PROJECT_ID", EncryptedValue: encrypt("ltvyvkdntvgicumfzgjy")},
		{Key: "VITE_API_URL", EncryptedValue: encrypt("https://api-a.example.com")},
	}}
	api := API{secrets: box}
	suggestions := api.appProxySuggestions(app)
	if len(suggestions) != 2 {
		t.Fatalf("expected Supabase and API suggestions, got %#v", suggestions)
	}
	if suggestions[0].AppID != "app-a" || suggestions[0].SupabaseProjectID != "ltvyvkdntvgicumfzgjy" || suggestions[0].Upstream != "https://ltvyvkdntvgicumfzgjy.supabase.co" {
		t.Fatalf("unexpected app-scoped Supabase suggestion: %#v", suggestions[0])
	}
	if suggestions[1].AppID != "app-a" || suggestions[1].Upstream != "https://api-a.example.com" {
		t.Fatalf("unexpected app-scoped API suggestion: %#v", suggestions[1])
	}
}

func TestValidateExternalUpstreamRejectsPrivateTargets(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:8080", "http://10.0.0.5", "http://169.254.169.254/latest", "http://service.default.svc.cluster.local"} {
		if _, err := validateExternalUpstream(target); err == nil {
			t.Fatalf("expected SSRF target to be rejected: %s", target)
		}
	}
}

func TestExtractCaddyBasePreservesUnmanagedRoutes(t *testing.T) {
	current := `{ auto_https disable_redirects }
http://panel.example.com { reverse_proxy 127.0.0.1:9080 }
http://app.example.com, https://app.example.com {
  reverse_proxy app.default.svc.cluster.local:80
}

func TestRenderDropsLegacyGlobalBlock(t *testing.T) {
	state := State{CaddyBaseConfigs: map[string]string{"server": "{ auto_https disable_redirects }\nhttp://panel.example.com { reverse_proxy 127.0.0.1:9080 }"}}
	config := renderManagedCaddy(state, "server")
	if strings.Count(config, "auto_https disable_redirects") != 1 || !strings.Contains(config, "panel.example.com") {
		t.Fatalf("expected exactly one global block while preserving unmanaged site:\n%s", config)
	}
}
:443 {
  @dynamic_subscription path /s/*
}`
	base := extractCaddyBase(current, []App{{Domains: []Domain{{Host: "app.example.com"}}}}, []SubscriptionRouting{{Domains: []string{"dy.example.com"}}})
	if !strings.Contains(base, "panel.example.com") || strings.Contains(base, "app.example.com") || strings.Contains(base, "dynamic_subscription") {
		t.Fatalf("unexpected extracted base:\n%s", base)
	}
}

func TestAppendRevisionKeepsOneVersionPerGitCommit(t *testing.T) {
	items := []DeploymentRevision{{ID: "old", Image: "image:1", GitCommit: "abc"}}
	items = appendRevision(items, DeploymentRevision{ID: "new", Image: "image:2", GitCommit: "abc"})
	if len(items) != 1 || items[0].ID != "new" || items[0].Image != "image:2" {
		t.Fatalf("expected latest image to replace duplicate commit: %#v", items)
	}
}

func between(value, start, end string) string {
	startAt := strings.Index(value, start)
	if startAt < 0 {
		return ""
	}
	endAt := strings.Index(value[startAt+len(start):], end)
	if endAt < 0 {
		return value[startAt:]
	}
	return value[startAt : startAt+len(start)+endAt]
}
