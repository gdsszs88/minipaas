package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (a *API) adoptedDomainsUpdate(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var input struct {
		Domains []string `json:"domains"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	domains, seen := []string{}, map[string]bool{}
	for _, value := range input.Domains {
		host := strings.ToLower(strings.TrimSpace(value))
		if host == "" {
			continue
		}
		if !domainPattern.MatchString(host) {
			writeJSON(w, 400, map[string]string{"error": "域名格式不正确: " + host})
			return
		}
		if !seen[host] {
			seen[host] = true
			domains = append(domains, host)
		}
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	target := ""
	if app.ManagedMode == "adopted" && app.Namespace != "" && app.ServiceName != "" {
		target = fmt.Sprintf("%s.%s.svc.cluster.local:%d", app.ServiceName, app.Namespace, app.Port)
	} else {
		name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
		target = fmt.Sprintf("%s.minipaas-apps.svc.cluster.local:%d", name, app.Port)
	}
	block := ""
	if len(domains) > 0 {
		headers := []string{}
		for _, host := range domains {
			headers = append(headers, "http://"+host, "https://"+host)
		}
		block = "\n" + strings.Join(headers, ", ") + " {\n  encode zstd gzip\n  reverse_proxy " + target + "\n}\n"
	}
	script := fmt.Sprintf(`set -euo pipefail
file=/tmp/Caddyfile-minipaas-adopted
new=/tmp/Caddyfile-minipaas-adopted-new
block=/tmp/Caddyfile-minipaas-adopted-block
domainfile=/tmp/Caddyfile-minipaas-adopted-domains
k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}' > "$file"
printf '%%s' '%s' | base64 -d > "$block"
printf '%%s' '%s' | base64 -d > "$domainfile"
python3 - "$file" "$new" '%s' "$block" "$domainfile" <<'PY'
import sys
source, output, target, block_path, domain_path = sys.argv[1:]
domains = [line.strip() for line in open(domain_path, encoding='utf-8') if line.strip()]
lines = open(source, encoding='utf-8').readlines()
result, current, depth = [], [], 0
for line in lines:
    if depth == 0 and line.strip().endswith('{'):
        current = [line]
        depth = line.count('{') - line.count('}')
        continue
    if depth > 0:
        current.append(line)
        depth += line.count('{') - line.count('}')
        if depth == 0:
            text = ''.join(current)
            header = current[0] if current else ''
            domain_match = any(('http://' + d) in header or ('https://' + d) in header for d in domains)
            if target not in text and not domain_match:
                result.append(text)
            current = []
        continue
    result.append(line)
if current and target not in ''.join(current):
    result.extend(current)
block = open(block_path, encoding='utf-8').read()
if block:
    result.append(block)
open(output, 'w', encoding='utf-8').write(''.join(result))
PY
k3s kubectl -n default create configmap independent-caddy-config --from-file=Caddyfile="$new" --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl -n default rollout restart daemonset independent-caddy
k3s kubectl -n default rollout status daemonset independent-caddy --timeout=120s
`, base64.StdEncoding.EncodeToString([]byte(block)), base64.StdEncoding.EncodeToString([]byte(strings.Join(domains, "\n"))), target)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	output, runErr := client.run(ctx, script, 150*time.Second)
	if runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "更新域名路由失败", "output": tailText(output, 6000)})
		return
	}
	err = a.store.mutate(func(s *State) error {
		for i := range s.Apps {
			if s.Apps[i].ID != app.ID {
				continue
			}
			s.Apps[i].Domains = nil
			for _, host := range domains {
				s.Apps[i].Domains = append(s.Apps[i].Domains, Domain{Host: host, HTTPS: true, Status: "active", TargetPort: app.Port})
			}
			s.Apps[i].UpdatedAt = time.Now()
		}
		appendAudit(s, "app.domains.update", app.ID, fmt.Sprintf("已更新接管应用 %s 的域名（%d 个）", app.Name, len(domains)), nil)
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "domains": domains})
}

func (a *API) promoteAdoptedApp(w http.ResponseWriter, r *http.Request) {
	old, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if old.ManagedMode != "adopted" {
		writeJSON(w, 400, map[string]string{"error": "该应用已经是原生管理"})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	baseName := strings.TrimSuffix(old.Name, "（已接管）")
	appID := newID("app")
	localImage := fmt.Sprintf("localhost/minipaas/imported-%s:%d", kubeName(baseName), time.Now().Unix())
	script := fmt.Sprintf(`set -euo pipefail
source_image=$(printf '%%s' '%s' | base64 -d)
target_image=$(printf '%%s' '%s' | base64 -d)
k3s ctr -n k8s.io images tag --force "$source_image" "$target_image"
k3s ctr -n k8s.io images list -q | grep -Fx "$target_image"
`, base64.StdEncoding.EncodeToString([]byte(old.Image)), base64.StdEncoding.EncodeToString([]byte(localImage)))
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if output, runErr := client.run(ctx, script, 90*time.Second); runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "归档现有镜像失败", "output": tailText(output, 5000)})
		return
	}
	now := time.Now()
	native := App{ID: appID, Name: baseName, ServerID: old.ServerID, SourceType: "image", BuildType: "image", Status: "draft", Image: old.Image, Port: old.Port, Variables: old.Variables, Domains: old.Domains, AutoDeploy: true, CreatedAt: now, UpdatedAt: now}
	err = a.store.mutate(func(s *State) error {
		for _, app := range s.Apps {
			if app.ManagedMode == "" && app.Name == baseName {
				return errors.New("已存在同名原生应用")
			}
		}
		s.Apps = append(s.Apps, native)
		appendAudit(s, "app.promote", native.ID, "已将接管应用归档为原生镜像应用："+baseName, map[string]any{"source": old.ID})
		return nil
	})
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, redactApp(native))
}

type kubeDeploymentList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int `json:"replicas"`
			Template struct {
				Spec struct {
					Containers []struct {
						Image string `json:"image"`
						Ports []struct {
							ContainerPort int `json:"containerPort"`
						} `json:"ports"`
						Env []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"env"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
		Status struct {
			AvailableReplicas int `json:"availableReplicas"`
		} `json:"status"`
	} `json:"items"`
}

type kubePVCList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Resources struct {
				Requests map[string]string `json:"requests"`
			} `json:"resources"`
		} `json:"spec"`
	} `json:"items"`
}

var adoptedProxyPattern = regexp.MustCompile(`reverse_proxy\s+([a-z0-9-]+)\.([a-z0-9-]+)\.svc\.cluster\.local:(\d+)`)
var caddyDomainPattern = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+)`)

func splitAdoptionOutput(output string) (string, string, string, error) {
	const depMarker = "===DEPLOYMENTS==="
	const pvcMarker = "===PVCS==="
	const caddyMarker = "===CADDY==="
	depAt, pvcAt, caddyAt := strings.Index(output, depMarker), strings.Index(output, pvcMarker), strings.Index(output, caddyMarker)
	if depAt < 0 || pvcAt < 0 || caddyAt < 0 || !(depAt < pvcAt && pvcAt < caddyAt) {
		return "", "", "", errors.New("服务器扫描结果格式不完整")
	}
	return strings.TrimSpace(output[depAt+len(depMarker) : pvcAt]), strings.TrimSpace(output[pvcAt+len(pvcMarker) : caddyAt]), strings.TrimSpace(output[caddyAt+len(caddyMarker):]), nil
}

func domainsByNamespace(caddy string) map[string][]string {
	result := map[string][]string{}
	lines := strings.Split(caddy, "\n")
	header := ""
	depth := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if depth == 0 && strings.HasSuffix(line, "{") {
			header = line
		}
		if match := adoptedProxyPattern.FindStringSubmatch(line); len(match) == 4 {
			key := match[2] + "/" + match[1]
			seen := map[string]bool{}
			for _, existing := range result[key] {
				seen[existing] = true
			}
			for _, domain := range caddyDomainPattern.FindAllStringSubmatch(header, -1) {
				if len(domain) == 2 && !seen[domain[1]] {
					result[key] = append(result[key], domain[1])
					seen[domain[1]] = true
				}
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			depth, header = 0, ""
		}
	}
	return result
}

func envValue(env []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}, name string) string {
	for _, item := range env {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

func storageGi(value string) int {
	value = strings.TrimSpace(strings.TrimSuffix(value, "Gi"))
	n, _ := strconv.Atoi(value)
	if n < 1 {
		return 1
	}
	return n
}

func (a *API) adoptExisting(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state := a.store.Snapshot()
	var server Server
	for _, item := range state.Servers {
		if item.ID == id {
			server = item
			break
		}
	}
	if server.ID == "" {
		writeJSON(w, 404, map[string]string{"error": "服务器不存在"})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	script := `set -e
printf '%s\n' '===DEPLOYMENTS==='
k3s kubectl get deployments -A -o json
printf '%s\n' '===PVCS==='
k3s kubectl get pvc -A -o json
printf '%s\n' '===CADDY==='
k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}'
`
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	output, err := client.run(ctx, script, 90*time.Second)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "扫描 K3s 资源失败", "output": tailText(output, 4000)})
		return
	}
	depJSON, pvcJSON, caddy, err := splitAdoptionOutput(output)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	var deployments kubeDeploymentList
	var pvcs kubePVCList
	if err := json.Unmarshal([]byte(depJSON), &deployments); err != nil {
		writeJSON(w, 502, map[string]string{"error": "无法解析工作负载"})
		return
	}
	if err := json.Unmarshal([]byte(pvcJSON), &pvcs); err != nil {
		writeJSON(w, 502, map[string]string{"error": "无法解析数据卷"})
		return
	}
	domains := domainsByNamespace(caddy)
	appsAdded, databasesAdded := 0, 0
	err = a.store.mutate(func(s *State) error {
		now := time.Now()
		for _, deployment := range deployments.Items {
			ns := deployment.Metadata.Namespace
			if (!strings.HasPrefix(ns, "independent-") && ns != "minipaas-apps") || len(deployment.Spec.Template.Spec.Containers) == 0 {
				continue
			}
			container := deployment.Spec.Template.Spec.Containers[0]
			isIndependentApp := strings.HasPrefix(ns, "independent-") && deployment.Metadata.Name == "app"
			isOrphanedMiniPaaSApp := ns == "minipaas-apps" && strings.HasPrefix(deployment.Metadata.Name, "mp-")
			if isOrphanedMiniPaaSApp {
				for _, existing := range s.Apps {
					if existing.ManagedMode == "" && "mp-"+kubeName(existing.Name)+"-"+idSuffix(existing.ID) == deployment.Metadata.Name {
						isOrphanedMiniPaaSApp = false
						break
					}
				}
			}
			if isIndependentApp || isOrphanedMiniPaaSApp {
				existingIndex := -1
				for i, app := range s.Apps {
					if app.ManagedMode == "adopted" && app.Namespace == ns && app.Workload == deployment.Metadata.Name {
						existingIndex = i
						break
					}
				}
				port := 8080
				if len(container.Ports) > 0 && container.Ports[0].ContainerPort > 0 {
					port = container.Ports[0].ContainerPort
				}
				variables := []Variable{}
				for _, item := range container.Env {
					if item.Name == "" || item.Value == "" || strings.HasPrefix(item.Name, "ZEABUR_") {
						continue
					}
					cipher, encryptErr := a.secrets.Encrypt([]byte(item.Value))
					if encryptErr != nil {
						return encryptErr
					}
					variables = append(variables, Variable{Key: item.Name, EncryptedValue: cipher, Secret: true})
				}
				if existingIndex >= 0 {
					// A rescan is also a safe way to refresh credentials from the
					// live workload after an external change or an older UI bug.
					s.Apps[existingIndex].Variables = variables
					s.Apps[existingIndex].Image = container.Image
					s.Apps[existingIndex].Port = port
					s.Apps[existingIndex].UpdatedAt = now
					continue
				}
				appDomains := []Domain{}
				serviceName := deployment.Metadata.Name
				if isIndependentApp {
					serviceName = "app"
				}
				for _, host := range domains[ns+"/"+serviceName] {
					appDomains = append(appDomains, Domain{Host: host, HTTPS: true, Status: "active", TargetPort: port})
				}
				status := "stopped"
				if deployment.Status.AvailableReplicas > 0 {
					status = "running"
				}
				nameBase := strings.TrimPrefix(ns, "independent-")
				if isOrphanedMiniPaaSApp {
					nameBase = strings.TrimPrefix(deployment.Metadata.Name, "mp-")
					if cut := strings.LastIndex(nameBase, "-"); cut > 0 {
						nameBase = nameBase[:cut]
					}
				}
				name := nameBase + "（已接管）"
				s.Apps = append(s.Apps, App{ID: newID("adopted"), Name: name, ServerID: id, SourceType: "existing", BuildType: "existing", Status: status, Image: container.Image, Port: port, Variables: variables, Domains: appDomains, CreatedAt: now, UpdatedAt: now, ManagedMode: "adopted", Namespace: ns, Workload: deployment.Metadata.Name, ServiceName: serviceName, DeployLog: "已从现有 K3s 工作负载无停机接管。"})
				appsAdded++
			} else if strings.HasPrefix(ns, "independent-") && deployment.Metadata.Name == "database" {
				exists := false
				for _, database := range s.Databases {
					if database.ManagedMode == "adopted" && database.Namespace == ns {
						exists = true
						break
					}
				}
				if exists {
					continue
				}
				pvcName, storage := "data", 1
				for _, pvc := range pvcs.Items {
					if pvc.Metadata.Namespace == ns {
						pvcName, storage = pvc.Metadata.Name, storageGi(pvc.Spec.Resources.Requests["storage"])
						break
					}
				}
				password := envValue(container.Env, "POSTGRES_PASSWORD")
				passwordCipher := ""
				if password != "" {
					passwordCipher, err = a.secrets.Encrypt([]byte(password))
					if err != nil {
						return err
					}
				}
				status := "stopped"
				if deployment.Status.AvailableReplicas > 0 {
					status = "running"
				}
				s.Databases = append(s.Databases, Database{ID: newID("adopteddb"), Name: strings.TrimPrefix(ns, "independent-") + " PostgreSQL（已接管）", Engine: "postgresql", Version: strings.TrimPrefix(container.Image, "docker.io/library/postgres:"), ServerID: id, Status: status, StorageGB: storage, Username: envValue(container.Env, "POSTGRES_USER"), DatabaseName: envValue(container.Env, "POSTGRES_DB"), Host: "database." + ns + ".svc.cluster.local", Port: 5432, PasswordCipher: passwordCipher, CreatedAt: now, ManagedMode: "adopted", Namespace: ns, Workload: deployment.Metadata.Name, ServiceName: "database", PVCName: pvcName})
				databasesAdded++
			}
		}
		appendAudit(s, "server.adopt", id, fmt.Sprintf("已无停机接管 %d 个应用和 %d 个数据库", appsAdded, databasesAdded), nil)
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "appsAdded": appsAdded, "databasesAdded": databasesAdded})
}
