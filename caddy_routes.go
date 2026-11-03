package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSupabaseUpstream = "https://ltvyvkdntvgicumfzgjy.supabase.co"
	defaultSupabaseHost     = "ltvyvkdntvgicumfzgjy.supabase.co"
)

var (
	proxyPathPattern   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/\-*]*$`)
	headerNamePattern  = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)
	forbiddenHostnames = map[string]bool{
		"localhost": true, "localhost.localdomain": true, "metadata.google.internal": true,
		"kubernetes.default": true, "kubernetes.default.svc": true,
	}
)

type proxyRoutePayload struct {
	Routes              []ProxyRoute `json:"routes"`
	SubscriptionDomains []string     `json:"subscriptionDomains,omitempty"`
}

func defaultSubscriptionRouting() SubscriptionRouting {
	return SubscriptionRouting{Enabled: true, Domains: []string{"dy.ip520.top"}, Upstream: defaultSupabaseUpstream, UpstreamHost: defaultSupabaseHost, AuthorizationURL: defaultSupabaseUpstream + "/functions/v1/subscription/domain-authorized"}
}

func (a *API) ensureRoutingDefaults() {
	_ = a.store.mutate(func(s *State) error {
		if s.CaddyBaseConfigs == nil {
			s.CaddyBaseConfigs = map[string]string{}
		}
		if strings.TrimSpace(s.SubscriptionRouting.Upstream) == "" {
			s.SubscriptionRouting = defaultSubscriptionRouting()
		}
		for i := range s.Apps {
			if len(s.Apps[i].Revisions) > 0 {
				collapsed := make([]DeploymentRevision, 0, len(s.Apps[i].Revisions))
				for _, revision := range s.Apps[i].Revisions {
					collapsed = appendRevision(collapsed, revision)
				}
				s.Apps[i].Revisions = collapsed
			}
			if !strings.EqualFold(s.Apps[i].Name, "jiedianshangcheng3.0") {
				continue
			}
			found := false
			for _, route := range s.Apps[i].ProxyRoutes {
				if route.PathPrefix == "/supabase/*" {
					found = true
				}
			}
			if !found {
				s.Apps[i].ProxyRoutes = append(s.Apps[i].ProxyRoutes, ProxyRoute{ID: newID("route"), Name: "Supabase 同源代理", Enabled: true, PathPrefix: "/supabase/*", Upstream: defaultSupabaseUpstream, StripPrefix: true, UpstreamHost: defaultSupabaseHost, Streaming: true, Sort: 10})
				s.Apps[i].UpdatedAt = time.Now()
			}
		}
		return nil
	})
}

func normalizedSubscription(value SubscriptionRouting) SubscriptionRouting {
	if strings.TrimSpace(value.Upstream) == "" {
		return defaultSubscriptionRouting()
	}
	if value.UpstreamHost == "" {
		value.UpstreamHost = defaultSupabaseHost
	}
	if value.AuthorizationURL == "" {
		value.AuthorizationURL = strings.TrimRight(value.Upstream, "/") + "/functions/v1/subscription/domain-authorized"
	}
	return value
}

func forbiddenUpstreamIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("100.100.100.200")) {
		return true
	}
	return false
}

func validateExternalUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("上游地址必须是完整的 HTTP/HTTPS 地址，且不能包含账号、查询参数或片段")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if forbiddenHostnames[host] || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local") {
		return nil, fmt.Errorf("禁止代理本机、内网、Kubernetes 或元数据地址")
	}
	if parsed := net.ParseIP(host); parsed != nil {
		if forbiddenUpstreamIP(parsed) {
			return nil, fmt.Errorf("禁止代理私有网段、环回或元数据地址")
		}
		return u, nil
	}
	if !domainPattern.MatchString(host) {
		return nil, fmt.Errorf("上游域名格式不正确")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addresses, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if lookupErr != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("无法解析上游域名")
	}
	for _, address := range addresses {
		if forbiddenUpstreamIP(address) {
			return nil, fmt.Errorf("上游域名解析到了禁止的内网、环回或元数据地址")
		}
	}
	return u, nil
}

func normalizeProxyRoutes(routes []ProxyRoute) ([]ProxyRoute, error) {
	result, ids := make([]ProxyRoute, 0, len(routes)), map[string]bool{}
	for index, route := range routes {
		route.Name = strings.TrimSpace(route.Name)
		route.PathPrefix = strings.TrimSpace(route.PathPrefix)
		route.Upstream = strings.TrimRight(strings.TrimSpace(route.Upstream), "/")
		route.UpstreamHost = strings.ToLower(strings.TrimSpace(route.UpstreamHost))
		if route.Name == "" || route.PathPrefix == "" || route.Upstream == "" {
			return nil, fmt.Errorf("第 %d 条路由缺少名称、路径或上游", index+1)
		}
		if !strings.HasPrefix(route.PathPrefix, "/") || !proxyPathPattern.MatchString(route.PathPrefix) || strings.Contains(route.PathPrefix, "..") {
			return nil, fmt.Errorf("路由 %s 的路径格式不安全", route.Name)
		}
		if !strings.HasSuffix(route.PathPrefix, "*") {
			route.PathPrefix = strings.TrimRight(route.PathPrefix, "/") + "/*"
		}
		u, err := validateExternalUpstream(route.Upstream)
		if err != nil {
			return nil, fmt.Errorf("路由 %s: %w", route.Name, err)
		}
		if route.UpstreamHost == "" {
			route.UpstreamHost = u.Hostname()
		}
		if !domainPattern.MatchString(route.UpstreamHost) || net.ParseIP(route.UpstreamHost) != nil {
			return nil, fmt.Errorf("路由 %s 的 Host 请求头格式不正确", route.Name)
		}
		for headerIndex := range route.RequestHeaders {
			header := &route.RequestHeaders[headerIndex]
			header.Name, header.Value = strings.TrimSpace(header.Name), strings.TrimSpace(header.Value)
			if !headerNamePattern.MatchString(header.Name) || strings.ContainsAny(header.Value, "\r\n") {
				return nil, fmt.Errorf("路由 %s 包含不安全的请求头", route.Name)
			}
		}
		if route.ID == "" || ids[route.ID] {
			route.ID = newID("route")
		}
		ids[route.ID] = true
		result = append(result, route)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Sort < result[j].Sort })
	return result, nil
}

func normalizeDomains(values []string) ([]string, error) {
	result, seen := []string{}, map[string]bool{}
	for _, value := range values {
		host := strings.ToLower(strings.TrimSpace(value))
		if host == "" {
			continue
		}
		if !domainPattern.MatchString(host) || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("域名格式不正确: %s", host)
		}
		if !seen[host] {
			seen[host], result = true, append(result, host)
		}
	}
	return result, nil
}

func caddyQuote(value string) string {
	return strconv.Quote(value)
}

func appCaddyTarget(app App) string {
	if app.ManagedMode == "adopted" && app.Namespace != "" && app.ServiceName != "" {
		return fmt.Sprintf("%s.%s.svc.cluster.local:%d", app.ServiceName, app.Namespace, app.Port)
	}
	return fmt.Sprintf("mp-%s-%s.minipaas-apps.svc.cluster.local:%d", kubeName(app.Name), idSuffix(app.ID), app.Port)
}

func renderProxyRoute(route ProxyRoute) string {
	directive := "handle"
	if route.StripPrefix {
		directive = "handle_path"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  # %s (sort %d)\n  %s %s {\n    reverse_proxy %s {\n", route.Name, route.Sort, directive, route.PathPrefix, route.Upstream)
	if route.UpstreamHost != "" {
		fmt.Fprintf(&b, "      header_up Host %s\n", caddyQuote(route.UpstreamHost))
	}
	for _, header := range route.RequestHeaders {
		fmt.Fprintf(&b, "      header_up %s %s\n", header.Name, caddyQuote(header.Value))
	}
	if route.Streaming {
		b.WriteString("      flush_interval -1\n")
	}
	b.WriteString("    }\n  }\n\n")
	return b.String()
}

func renderManagedCaddy(state State, serverID string) string {
	base := strings.TrimSpace(state.CaddyBaseConfigs[serverID])
	subscription := normalizedSubscription(state.SubscriptionRouting)
	if !strings.Contains(base, "on_demand_tls") {
		base = fmt.Sprintf("{\n  auto_https disable_redirects\n  on_demand_tls {\n    ask %s\n  }\n}\n\n%s", subscription.AuthorizationURL, base)
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(base))
	b.WriteString("\n\n# BEGIN MINIPAAS PERSISTENT ROUTES\n")
	apps := append([]App(nil), state.Apps...)
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	for _, app := range apps {
		if app.ServerID != serverID || len(app.Domains) == 0 {
			continue
		}
		headers := []string{}
		for _, domain := range app.Domains {
			if domainPattern.MatchString(domain.Host) {
				headers = append(headers, "http://"+domain.Host, "https://"+domain.Host)
			}
		}
		if len(headers) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n# app:%s %s\n%s {\n  encode zstd gzip\n\n", app.ID, app.Name, strings.Join(headers, ", "))
		routes := append([]ProxyRoute(nil), app.ProxyRoutes...)
		sort.SliceStable(routes, func(i, j int) bool { return routes[i].Sort < routes[j].Sort })
		for _, route := range routes {
			if route.Enabled {
				b.WriteString(renderProxyRoute(route))
			}
		}
		fmt.Fprintf(&b, "  handle {\n    reverse_proxy %s\n  }\n}\n", appCaddyTarget(app))
	}
	if subscription.Enabled {
		domains, _ := normalizeDomains(subscription.Domains)
		if len(domains) > 0 {
			headers := []string{}
			for _, domain := range domains {
				headers = append(headers, "http://"+domain, "https://"+domain)
			}
			fmt.Fprintf(&b, "\n# subscription:explicit\n%s {\n  encode zstd gzip\n  @subscription path_regexp subscription ^/s/([0-9a-fA-F-]+)$\n  handle @subscription {\n    rewrite * /functions/v1/subscription?token={re.subscription.1}\n    reverse_proxy %s {\n      header_up Host %s\n      flush_interval -1\n    }\n  }\n  respond \"订阅地址无效\" 404\n}\n", strings.Join(headers, ", "), subscription.Upstream, caddyQuote(subscription.UpstreamHost))
		}
		for _, port := range []string{":80", ":443"} {
			fmt.Fprintf(&b, "\n%s {\n", port)
			if port == ":443" {
				b.WriteString("  tls {\n    on_demand\n  }\n")
			}
			fmt.Fprintf(&b, "  @dynamic_subscription path_regexp dynamic_subscription ^/s/([0-9a-fA-F-]+)$\n  handle @dynamic_subscription {\n    rewrite * /functions/v1/subscription?token={re.dynamic_subscription.1}\n    reverse_proxy %s {\n      header_up Host %s\n      flush_interval -1\n    }\n  }\n  respond \"订阅地址无效\" 404\n}\n", subscription.Upstream, caddyQuote(subscription.UpstreamHost))
		}
	}
	b.WriteString("\n# END MINIPAAS PERSISTENT ROUTES\n")
	return b.String()
}

func extractCaddyBase(current string, apps []App, subscription SubscriptionRouting) string {
	domains := map[string]bool{}
	for _, app := range apps {
		for _, domain := range app.Domains {
			domains[strings.ToLower(domain.Host)] = true
		}
	}
	for _, domain := range subscription.Domains {
		domains[strings.ToLower(domain)] = true
	}
	lines := strings.Split(current, "\n")
	var result, block []string
	depth := 0
	keepBlock := func(lines []string) {
		text := strings.Join(lines, "\n")
		header := strings.ToLower(strings.TrimSpace(lines[0]))
		managed := strings.Contains(text, "MINIPAAS PERSISTENT ROUTES") || strings.Contains(text, "dynamic_subscription")
		for domain := range domains {
			if strings.Contains(header, "http://"+domain) || strings.Contains(header, "https://"+domain) {
				managed = true
			}
		}
		if !managed {
			result = append(result, text)
		}
	}
	for _, line := range lines {
		if depth == 0 && strings.Contains(line, "{") {
			block = []string{line}
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			if depth > 0 {
				continue
			}
			keepBlock(block)
			block = nil
			continue
		}
		if depth > 0 {
			block = append(block, line)
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth > 0 {
				continue
			}
			keepBlock(block)
			block = nil
			continue
		}
		if len(block) == 0 {
			result = append(result, line)
		}
	}
	return strings.TrimSpace(strings.Join(result, "\n"))
}

func (a *API) applyCaddyForServer(ctx context.Context, serverID string) (bool, string, error) {
	a.caddyMu.Lock()
	defer a.caddyMu.Unlock()
	state := a.store.Snapshot()
	var server Server
	for _, item := range state.Servers {
		if item.ID == serverID {
			server = item
			break
		}
	}
	if server.ID == "" {
		return false, "", fmt.Errorf("目标服务器不存在")
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		return false, "", fmt.Errorf("无法读取服务器凭据")
	}
	client := RemoteClient{Server: server, PrivateKey: key}
	current, err := client.run(ctx, `k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}'`, 30*time.Second)
	if err != nil {
		return false, current, fmt.Errorf("无法读取 Caddy ConfigMap: %w", err)
	}
	if strings.TrimSpace(state.CaddyBaseConfigs[serverID]) == "" {
		base := extractCaddyBase(current, state.Apps, normalizedSubscription(state.SubscriptionRouting))
		if err := a.store.mutate(func(s *State) error {
			if s.CaddyBaseConfigs == nil {
				s.CaddyBaseConfigs = map[string]string{}
			}
			if strings.TrimSpace(s.CaddyBaseConfigs[serverID]) == "" {
				s.CaddyBaseConfigs[serverID] = base
			}
			return nil
		}); err != nil {
			return false, "", err
		}
		state = a.store.Snapshot()
	}
	desired := renderManagedCaddy(state, serverID)
	if strings.TrimSpace(current) == strings.TrimSpace(desired) {
		return false, "Caddy 配置无变化，已跳过重启", nil
	}
	script := fmt.Sprintf(`set -euo pipefail
backup_dir=/var/lib/minipaas/caddy-backups
mkdir -p "$backup_dir"
stamp=$(date +%%F_%%H-%%M-%%S)
old=/tmp/Caddyfile.minipaas.old
new=/tmp/Caddyfile.minipaas.new
backup="$backup_dir/configmap-$stamp.yaml"
k3s kubectl -n default get configmap independent-caddy-config -o yaml > "$backup"
k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}' > "$old"
printf '%%s' '%s' | base64 -d > "$new"
if cmp -s "$old" "$new"; then echo MINIPAAS_CADDY_UNCHANGED; exit 0; fi
pod=$(k3s kubectl -n default get pod -l app=independent-caddy -o jsonpath='{.items[0].metadata.name}')
test -n "$pod"
cat "$new" | k3s kubectl -n default exec -i "$pod" -- sh -c 'cat >/tmp/Caddyfile.validate && caddy validate --config /tmp/Caddyfile.validate --adapter caddyfile'
k3s kubectl -n default create configmap independent-caddy-config --from-file=Caddyfile="$new" --dry-run=client -o yaml | k3s kubectl apply -f -
if ! k3s kubectl -n default rollout restart daemonset independent-caddy || ! k3s kubectl -n default rollout status daemonset independent-caddy --timeout=150s; then
  k3s kubectl apply -f "$backup"
  k3s kubectl -n default rollout restart daemonset independent-caddy || true
  k3s kubectl -n default rollout status daemonset independent-caddy --timeout=150s || true
  echo MINIPAAS_CADDY_ROLLED_BACK
  exit 31
fi
find "$backup_dir" -type f -name 'configmap-*.yaml' -mtime +30 -delete
echo MINIPAAS_CADDY_APPLIED
`, base64.StdEncoding.EncodeToString([]byte(desired)))
	output, runErr := client.run(ctx, script, 4*time.Minute)
	if runErr != nil {
		return false, output, fmt.Errorf("Caddy 校验或应用失败，旧配置已保留: %w", runErr)
	}
	return true, output, nil
}

func (a *API) appProxyRoutes(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if r.Method == http.MethodGet {
		state := a.store.Snapshot()
		writeJSON(w, http.StatusOK, map[string]any{"appId": app.ID, "app": app.Name, "routes": app.ProxyRoutes, "subscriptionDomains": normalizedSubscription(state.SubscriptionRouting).Domains})
		return
	}
	var input proxyRoutePayload
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	routes, err := normalizeProxyRoutes(input.Routes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	domains, err := normalizeDomains(input.SubscriptionDomains)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	before := a.store.Snapshot()
	if err := a.store.mutate(func(s *State) error {
		for i := range s.Apps {
			if s.Apps[i].ID == app.ID {
				s.Apps[i].ProxyRoutes, s.Apps[i].UpdatedAt = routes, time.Now()
			}
		}
		if len(domains) > 0 {
			sub := normalizedSubscription(s.SubscriptionRouting)
			merged := append(append([]string(nil), sub.Domains...), domains...)
			sub.Domains, _ = normalizeDomains(merged)
			s.SubscriptionRouting = sub
		}
		appendAudit(s, "app.proxy-routes.update", app.ID, "已更新应用 "+app.Name+" 的反向代理路由", map[string]any{"routes": len(routes)})
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	changed, output, applyErr := a.applyCaddyForServer(ctx, server.ID)
	if applyErr != nil {
		_ = a.store.mutate(func(s *State) error { *s = before; return nil })
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": applyErr.Error(), "output": tailText(output, 6000)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "routes": routes, "output": tailText(output, 6000)})
}

func (a *API) appProxyRouteHealth(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	changed, applyOutput, err := a.applyCaddyForServer(ctx, server.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "output": tailText(applyOutput, 6000)})
		return
	}
	key, _ := a.secrets.Decrypt(server.Credential)
	client := RemoteClient{Server: server, PrivateKey: key}
	var checks []string
	for _, domain := range app.Domains {
		for _, route := range app.ProxyRoutes {
			if route.Enabled {
				path := strings.TrimSuffix(route.PathPrefix, "*")
				checks = append(checks, fmt.Sprintf("printf '%%s ' '%s%s'; curl -sS -o /dev/null -w 'HTTP %%{http_code} time=%%{time_total}s\\n' --max-time 20 '%s%s' || true", domain.Host, path, "https://"+domain.Host, path))
			}
		}
	}
	output, runErr := client.run(ctx, strings.Join(checks, "\n"), 90*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"ok": runErr == nil, "changed": changed, "caddy": tailText(applyOutput, 3000), "checks": tailText(output, 6000)})
}

func (a *API) appProxyRouteExport(w http.ResponseWriter, r *http.Request) {
	app, _, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	payload := map[string]any{"version": 1, "app": app.Name, "appId": app.ID, "routes": app.ProxyRoutes, "subscriptionRouting": normalizedSubscription(a.store.Snapshot().SubscriptionRouting), "exportedAt": time.Now()}
	w.Header().Set("Content-Disposition", `attachment; filename="minipaas-proxy-routes.json"`)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *API) appProxyRouteRestore(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version             int                 `json:"version"`
		App                 string              `json:"app"`
		AppID               string              `json:"appId"`
		ExportedAt          time.Time           `json:"exportedAt"`
		Routes              []ProxyRoute        `json:"routes"`
		SubscriptionRouting SubscriptionRouting `json:"subscriptionRouting"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	requestBody, _ := json.Marshal(proxyRoutePayload{Routes: input.Routes, SubscriptionDomains: input.SubscriptionRouting.Domains})
	clone := r.Clone(r.Context())
	clone.Method = http.MethodPut
	clone.Body = http.NoBody
	clone.ContentLength = int64(len(requestBody))
	clone.Body = ioNopCloser{strings.NewReader(string(requestBody))}
	a.appProxyRoutes(w, clone)
}

type ioNopCloser struct{ *strings.Reader }

func (ioNopCloser) Close() error { return nil }

func (a *API) runCaddyReconciler() {
	time.Sleep(30 * time.Second)
	for {
		state := a.store.Snapshot()
		for _, server := range state.Servers {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			_, _, _ = a.applyCaddyForServer(ctx, server.ID)
			cancel()
		}
		time.Sleep(10 * time.Minute)
	}
}
