package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type DomainHealth struct {
	Host            string    `json:"host"`
	DNS             []string  `json:"dns"`
	CaddyConfigured bool      `json:"caddyConfigured"`
	HTTPS           bool      `json:"https"`
	HTTPStatus      int       `json:"httpStatus,omitempty"`
	CertIssuer      string    `json:"certIssuer,omitempty"`
	CertExpiresAt   time.Time `json:"certExpiresAt,omitempty"`
	DaysRemaining   int       `json:"daysRemaining,omitempty"`
	Error           string    `json:"error,omitempty"`
	CheckedAt       time.Time `json:"checkedAt"`
}

func publicIPs(values []net.IP) []net.IP {
	result := []net.IP{}
	for _, ip := range values {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		result = append(result, ip)
	}
	return result
}

func inspectDomain(ctx context.Context, host string, caddyConfig string) DomainHealth {
	result := DomainHealth{Host: host, CaddyConfigured: strings.Contains(caddyConfig, "http://"+host) || strings.Contains(caddyConfig, "https://"+host), CheckedAt: time.Now()}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		result.Error = "DNS 解析失败: " + err.Error()
		return result
	}
	public := publicIPs(addresses)
	for _, ip := range addresses {
		result.DNS = append(result.DNS, ip.String())
	}
	sort.Strings(result.DNS)
	if len(public) == 0 {
		result.Error = "域名没有解析到公网 IP"
		return result
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(callCtx context.Context, network, address string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "" {
			port = "443"
		}
		return dialer.DialContext(callCtx, "tcp", net.JoinHostPort(public[0].String(), port))
	}}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	response, err := client.Do(request)
	if err != nil {
		result.Error = "HTTPS 连接失败: " + err.Error()
		return result
	}
	defer response.Body.Close()
	result.HTTPS, result.HTTPStatus = true, response.StatusCode
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		certificate := response.TLS.PeerCertificates[0]
		result.CertIssuer, result.CertExpiresAt = certificate.Issuer.CommonName, certificate.NotAfter
		result.DaysRemaining = int(time.Until(certificate.NotAfter).Hours() / 24)
	}
	return result
}

func (a *API) appDomainHealth(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if len(app.Domains) == 0 {
		writeJSON(w, 200, map[string]any{"domains": []DomainHealth{}})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	client := RemoteClient{Server: server, PrivateKey: key}
	remoteCtx, remoteCancel := context.WithTimeout(r.Context(), 20*time.Second)
	config, configErr := client.run(remoteCtx, `k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}'`, 15*time.Second)
	remoteCancel()
	if configErr != nil {
		config = ""
	}
	results := make([]DomainHealth, len(app.Domains))
	var wg sync.WaitGroup
	for i, domain := range app.Domains {
		wg.Add(1)
		go func(index int, host string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
			defer cancel()
			results[index] = inspectDomain(ctx, host, config)
		}(i, domain.Host)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"app": app.Name, "server": server.Name, "domains": results})
}
