package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type EnvironmentComponent struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
}

type SetupJob struct {
	ID         string                 `json:"id"`
	ServerID   string                 `json:"serverId"`
	Status     string                 `json:"status"`
	Mode       string                 `json:"mode"`
	Current    string                 `json:"current,omitempty"`
	Progress   int                    `json:"progress"`
	Completed  int                    `json:"completed"`
	Total      int                    `json:"total"`
	Log        []string               `json:"log"`
	Components []EnvironmentComponent `json:"components,omitempty"`
	Error      string                 `json:"error,omitempty"`
	StartedAt  time.Time              `json:"startedAt"`
	FinishedAt time.Time              `json:"finishedAt,omitempty"`
}

type setupStep struct {
	Name    string
	Command string
}

func environmentCatalog() []EnvironmentComponent {
	return []EnvironmentComponent{
		{ID: "base", Name: "基础系统工具", Category: "基础环境", Description: "curl、证书、Git、jq、压缩与同步工具"},
		{ID: "network", Name: "网络诊断工具", Category: "基础环境", Description: "DNS、端口、路由和抓包排障工具"},
		{ID: "buildah", Name: "容器构建工具", Category: "构建环境", Description: "Buildah、Skopeo 与 overlay 文件系统支持"},
		{ID: "k3s", Name: "K3s 容器平台", Category: "运行环境", Description: "应用、数据库、持久卷和滚动部署运行时"},
		{ID: "gateway", Name: "Caddy HTTPS 网关", Category: "域名环境", Description: "自动签发 HTTPS、绑定域名并转发到应用"},
		{ID: "clients", Name: "数据库客户端", Category: "数据库工具", Description: "PostgreSQL、MySQL、Redis 命令行客户端"},
		{ID: "security", Name: "安全防护工具", Category: "安全环境", Description: "Fail2ban、UFW；启用防火墙时自动放行 80/443"},
	}
}

func findServer(state State, id string) (Server, bool) {
	for _, server := range state.Servers {
		if server.ID == id {
			return server, true
		}
	}
	return Server{}, false
}

func (a *API) remoteForServer(id string) (RemoteClient, error) {
	server, ok := findServer(a.store.Snapshot(), id)
	if !ok {
		return RemoteClient{}, fmt.Errorf("服务器不存在")
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		return RemoteClient{}, fmt.Errorf("无法读取服务器凭据")
	}
	return RemoteClient{Server: server, PrivateKey: key}, nil
}

func inspectEnvironment(ctx context.Context, client RemoteClient) ([]EnvironmentComponent, error) {
	command := `set -eu
check(){ id="$1"; shift; version=""; installed=1; for cmd in "$@"; do if ! command -v "$cmd" >/dev/null 2>&1; then installed=0; fi; done; if [ "$installed" = 1 ]; then case "$id" in k3s) version=$(k3s --version 2>/dev/null | head -1);; buildah) version=$(buildah --version 2>/dev/null | head -1);; base) version=$(git --version 2>/dev/null | head -1);; clients) version="database clients ready";; security) version=$(fail2ban-client --version 2>/dev/null | head -1);; network) version="network tools ready";; esac; fi; printf '%s|%s|%s\n' "$id" "$installed" "$version"; }
check base curl git jq tar gzip unzip rsync openssl
check network dig nc ip ss tcpdump
check buildah buildah
check k3s k3s
if command -v k3s >/dev/null 2>&1 && k3s kubectl -n default get configmap independent-caddy-config >/dev/null 2>&1 && [ "$(k3s kubectl -n default get daemonset independent-caddy -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)" != "0" ]; then gateway_version=$(k3s kubectl -n default get daemonset independent-caddy -o jsonpath='{.spec.template.spec.containers[0].image}'); printf 'gateway|1|%s\n' "$gateway_version"; else printf 'gateway|0|\n'; fi
check clients psql mysql redis-cli
check security fail2ban-client ufw`
	out, err := client.run(ctx, command, 45*time.Second)
	if err != nil {
		return nil, fmt.Errorf("检测服务器环境失败: %w (%s)", err, tailText(out, 1200))
	}
	items := environmentCatalog()
	result := map[string][2]string{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(parts) == 3 {
			result[parts[0]] = [2]string{parts[1], parts[2]}
		}
	}
	for i := range items {
		if value, ok := result[items[i].ID]; ok {
			items[i].Installed = value[0] == "1"
			items[i].Version = strings.TrimSpace(value[1])
		}
	}
	return items, nil
}

func (a *API) serverEnvironment(w http.ResponseWriter, r *http.Request) {
	client, err := a.remoteForServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	items, err := inspectEnvironment(r.Context(), client)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	installed := 0
	for _, item := range items {
		if item.Installed {
			installed++
		}
	}
	ready := installed == len(items)
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Servers {
			if s.Servers[i].ID == client.Server.ID {
				s.Servers[i].EnvironmentReady = ready
				s.Servers[i].EnvironmentChecked = time.Now()
			}
		}
		return nil
	})
	writeJSON(w, 200, map[string]any{"components": items, "installed": installed, "total": len(items), "ready": ready})
}

func (a *API) serverEnvironmentInstall(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	client, err := a.remoteForServer(serverID)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var input struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if input.Mode == "" {
		input.Mode = "skip"
	}
	if input.Mode != "skip" && input.Mode != "force" {
		writeJSON(w, 400, map[string]string{"error": "安装模式只能是 skip 或 force"})
		return
	}
	a.setupMu.Lock()
	for _, existing := range a.setupJobs {
		if existing.ServerID == serverID && existing.Status == "running" {
			a.setupMu.Unlock()
			writeJSON(w, 409, map[string]string{"error": "该服务器已有初始化任务正在运行"})
			return
		}
	}
	job := &SetupJob{ID: newID("setup"), ServerID: serverID, Status: "running", Mode: input.Mode, Total: 9, StartedAt: time.Now(), Log: []string{"已连接服务器，准备检测软件环境。"}}
	a.setupJobs[job.ID] = job
	a.setupMu.Unlock()
	go a.runEnvironmentInstall(job.ID, client)
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) updateSetupJob(id string, fn func(*SetupJob)) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if job := a.setupJobs[id]; job != nil {
		fn(job)
	}
}

func (a *API) runEnvironmentInstall(jobID string, client RemoteClient) {
	a.setupMu.RLock()
	mode := a.setupJobs[jobID].Mode
	a.setupMu.RUnlock()
	reinstall := ""
	if mode == "force" {
		reinstall = " --reinstall"
	}
	steps := []setupStep{
		{Name: "刷新软件索引", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get update`},
		{Name: "安装基础系统工具", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get install -y` + reinstall + ` curl ca-certificates git jq tar gzip unzip rsync openssl`},
		{Name: "安装网络诊断工具", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get install -y` + reinstall + ` dnsutils netcat-openbsd iproute2 tcpdump`},
		{Name: "安装容器构建工具", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get install -y` + reinstall + ` buildah skopeo fuse-overlayfs uidmap`},
		{Name: "安装 K3s 容器平台", Command: func() string {
			if mode == "force" {
				return `set -eu; curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable traefik --write-kubeconfig-mode 600' sh -`
			}
			return `set -eu; if command -v k3s >/dev/null 2>&1; then echo 'K3s 已安装，自动跳过'; else curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable traefik --write-kubeconfig-mode 600' sh -; fi`
		}()},
		{Name: "安装数据库客户端", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get install -y` + reinstall + ` postgresql-client default-mysql-client redis-tools`},
		{Name: "安装安全防护工具", Command: `set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get install -y` + reinstall + ` fail2ban ufw`},
		{Name: "安装 Caddy HTTPS 网关", Command: caddyGatewayInstallCommand(mode == "force")},
		{Name: "检查并开放网站端口", Command: `set -eu
if ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
fi
k3s kubectl -n default rollout status daemonset/independent-caddy --timeout=180s
k3s kubectl -n default get daemonset independent-caddy -o wide
ss -lntup | grep -E ':(80|443)[[:space:]]' || { echo 'Caddy 尚未监听 80/443'; exit 1; }`},
	}
	for i, step := range steps {
		a.updateSetupJob(jobID, func(job *SetupJob) {
			job.Current = step.Name
			job.Progress = i * 100 / len(steps)
			job.Log = append(job.Log, fmt.Sprintf("[%d/%d] %s…", i+1, len(steps), step.Name))
		})
		out, err := client.run(context.Background(), step.Command, 20*time.Minute)
		if err != nil {
			a.updateSetupJob(jobID, func(job *SetupJob) {
				job.Status = "failed"
				job.Error = fmt.Sprintf("%s失败：%v", step.Name, err)
				job.Log = append(job.Log, tailText(out, 3000))
				job.FinishedAt = time.Now()
			})
			return
		}
		a.updateSetupJob(jobID, func(job *SetupJob) {
			job.Completed = i + 1
			job.Progress = (i + 1) * 100 / len(steps)
			job.Log = append(job.Log, "✓ "+step.Name+"完成")
		})
	}
	components, err := inspectEnvironment(context.Background(), client)
	ready := err == nil
	if ready {
		for _, component := range components {
			if !component.Installed {
				ready = false
				break
			}
		}
	}
	a.updateSetupJob(jobID, func(job *SetupJob) {
		job.Components = components
		job.Current = "完成"
		job.Progress = 100
		job.FinishedAt = time.Now()
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
			job.Log = append(job.Log, "安装完成，但最终检测失败："+err.Error())
		} else {
			job.Status = "completed"
			job.Log = append(job.Log, "全部环境组件安装并检测完成。")
		}
	})
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Servers {
			if s.Servers[i].ID == client.Server.ID {
				s.Servers[i].EnvironmentReady = ready
				s.Servers[i].EnvironmentChecked = time.Now()
			}
		}
		appendAudit(s, "server.environment", client.Server.ID, "服务器一键环境初始化完成", map[string]any{"mode": mode})
		return nil
	})
}

func caddyGatewayInstallCommand(force bool) string {
	guard := `if k3s kubectl -n default get configmap independent-caddy-config >/dev/null 2>&1 && k3s kubectl -n default get daemonset independent-caddy >/dev/null 2>&1; then echo 'Caddy HTTPS 网关已安装，自动跳过'; exit 0; fi`
	if force {
		guard = `echo '强制模式：重新应用 Caddy 网关运行配置（保留现有域名配置）'`
	}
	return `set -eu
` + guard + `
install -d -m 700 /var/lib/independent-caddy/data /var/lib/independent-caddy/config
if ! k3s kubectl -n default get configmap independent-caddy-config >/dev/null 2>&1; then
cat >/tmp/minipaas-caddy-config.yaml <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: independent-caddy-config
  namespace: default
data:
  Caddyfile: |
    {
      auto_https disable_redirects
    }
YAML
k3s kubectl apply -f /tmp/minipaas-caddy-config.yaml
fi
cat >/tmp/minipaas-caddy-daemonset.yaml <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: independent-caddy
  namespace: default
  labels:
    app: independent-caddy
spec:
  selector:
    matchLabels:
      app: independent-caddy
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: independent-caddy
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      terminationGracePeriodSeconds: 10
      containers:
      - name: caddy
        image: docker.io/library/caddy:2-alpine
        imagePullPolicy: IfNotPresent
        args: ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
        ports:
        - {name: http, containerPort: 80, protocol: TCP}
        - {name: https, containerPort: 443, protocol: TCP}
        - {name: https-udp, containerPort: 443, protocol: UDP}
        resources:
          requests: {cpu: 25m, memory: 32Mi}
          limits: {memory: 256Mi}
        volumeMounts:
        - {name: config, mountPath: /etc/caddy, readOnly: true}
        - {name: data, mountPath: /data}
        - {name: runtime-config, mountPath: /config}
      volumes:
      - name: config
        configMap: {name: independent-caddy-config}
      - name: data
        hostPath: {path: /var/lib/independent-caddy/data, type: DirectoryOrCreate}
      - name: runtime-config
        hostPath: {path: /var/lib/independent-caddy/config, type: DirectoryOrCreate}
YAML
k3s kubectl apply -f /tmp/minipaas-caddy-daemonset.yaml
k3s kubectl -n default rollout status daemonset/independent-caddy --timeout=180s`
}

func (a *API) setupJobStatus(w http.ResponseWriter, r *http.Request) {
	a.setupMu.RLock()
	job := a.setupJobs[r.PathValue("id")]
	if job == nil {
		a.setupMu.RUnlock()
		writeJSON(w, 404, map[string]string{"error": "安装任务不存在"})
		return
	}
	copy := *job
	copy.Log = append([]string(nil), job.Log...)
	copy.Components = append([]EnvironmentComponent(nil), job.Components...)
	a.setupMu.RUnlock()
	writeJSON(w, 200, copy)
}
