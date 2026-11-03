package main

import (
	"strings"
	"testing"
)

func TestRenderManagedCaddyOrdersProxyBeforeFallback(t *testing.T) {
	state := State{
		CaddyBaseConfigs:    map[string]string{"server": "{\n  auto_https disable_redirects\n}"},
		SubscriptionRouting: defaultSubscriptionRouting(),
		Apps: []App{{
			ID: "app_123456", Name: "jiedianshangcheng3.0", ServerID: "server", Port: 80,
			Domains:     []Domain{{Host: "www.ip520.top"}},
			ProxyRoutes: []ProxyRoute{{Name: "Supabase", Enabled: true, PathPrefix: "/supabase/*", Upstream: defaultSupabaseUpstream, StripPrefix: true, UpstreamHost: defaultSupabaseHost, Streaming: true, Sort: 10}},
		}},
	}
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

func TestAppendRevisionKeepsOneVersionPerGitCommit(t *testing.T) {
	items := []DeploymentRevision{{ID: "old", Image: "image:1", GitCommit: "abc"}}
	items = appendRevision(items, DeploymentRevision{ID: "new", Image: "image:2", GitCommit: "abc"})
	if len(items) != 1 || items[0].ID != "new" || items[0].Image != "image:2" {
		t.Fatalf("expected latest image to replace duplicate commit: %#v", items)
	}
}
:443 {
  @dynamic_subscription path /s/*
}`
	apps := []App{{Domains: []Domain{{Host: "app.example.com"}}}}
	base := extractCaddyBase(current, apps, defaultSubscriptionRouting())
	if !strings.Contains(base, "panel.example.com") || strings.Contains(base, "app.example.com") || strings.Contains(base, "dynamic_subscription") {
		t.Fatalf("unexpected extracted base:\n%s", base)
	}
}
