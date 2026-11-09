package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 自动清理：定时回收构建缓存与历史镜像，同时保证「最近成功部署的镜像」永不误删。
//
// 为什么不能只按镜像 tag 保留最新 N 个：部署失败的那次构建同样会留下一个 tag，
// 而且它的时间戳比上一次成功部署更大。按数字排序清理，会把真正健康的、可回滚的
// 镜像删掉，把废镜像留下。这里改为以控制面的成功部署记录（Revisions）为准，
// 再加上 K3s 里正在运行的镜像做双保险。
const maintenanceFileName = "maintenance.json"

type MaintenanceSettings struct {
	Enabled              bool              `json:"enabled"`
	KeepSuccessImages    int               `json:"keepSuccessImages"`
	IntervalHours        int               `json:"intervalHours"`
	CleanImageTar        bool              `json:"cleanImageTar"`
	VacuumJournal        bool              `json:"vacuumJournal"`
	KeepRecoveryPackages int               `json:"keepRecoveryPackages"`
	LastRunAt            *time.Time        `json:"lastRunAt,omitempty"`
	LastTrigger          string            `json:"lastTrigger,omitempty"`
	LastStatus           string            `json:"lastStatus,omitempty"`
	LastReclaimedMB      int64             `json:"lastReclaimedMB,omitempty"`
	LastLog              string            `json:"lastLog,omitempty"`
	LastServers          []MaintenanceNode `json:"lastServers,omitempty"`
}

type MaintenanceNode struct {
	ServerID      string   `json:"serverId"`
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Status        string   `json:"status"`
	Message       string   `json:"message,omitempty"`
	DiskPercent   int      `json:"diskPercent"`
	AvailGB       float64  `json:"availGB"`
	ImagesTotal   int      `json:"imagesTotal"`
	ImagesDeleted int      `json:"imagesDeleted"`
	ReclaimedMB   int64    `json:"reclaimedMB"`
	Protected     []string `json:"protected,omitempty"`
	Output        string   `json:"output,omitempty"`
}

func defaultMaintenanceSettings() MaintenanceSettings {
	return MaintenanceSettings{
		Enabled:              true,
		KeepSuccessImages:    2,
		IntervalHours:        6,
		CleanImageTar:        true,
		VacuumJournal:        true,
		KeepRecoveryPackages: 3,
	}
}

func normalizeMaintenanceSettings(s MaintenanceSettings) MaintenanceSettings {
	if s.KeepSuccessImages < 1 {
		s.KeepSuccessImages = 1
	}
	if s.KeepSuccessImages > 10 {
		s.KeepSuccessImages = 10
	}
	if s.IntervalHours < 1 {
		s.IntervalHours = 1
	}
	if s.IntervalHours > 24*30 {
		s.IntervalHours = 24 * 30
	}
	if s.KeepRecoveryPackages < 0 {
		s.KeepRecoveryPackages = 0
	}
	if s.KeepRecoveryPackages > 60 {
		s.KeepRecoveryPackages = 60
	}
	return s
}

// MaintenanceStore 把设置和上次运行结果保存在 /var/lib/minipaas/maintenance.json。
// 用独立文件而不是 state.json，是为了让升级、恢复旧备份都不会把清理策略重置掉。
type MaintenanceStore struct {
	mu   sync.Mutex
	path string
	data MaintenanceSettings
}

func openMaintenanceStore(dataDir string) *MaintenanceStore {
	s := &MaintenanceStore{path: filepath.Join(dataDir, maintenanceFileName), data: defaultMaintenanceSettings()}
	if raw, err := os.ReadFile(s.path); err == nil {
		loaded := MaintenanceSettings{}
		if json.Unmarshal(raw, &loaded) == nil {
			s.data = normalizeMaintenanceSettings(loaded)
		}
	}
	return s
}

func (s *MaintenanceStore) Snapshot() MaintenanceSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := s.data
	copy.LastServers = append([]MaintenanceNode(nil), s.data.LastServers...)
	return copy
}

func (s *MaintenanceStore) Update(change func(*MaintenanceSettings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(&s.data)
	s.data = normalizeMaintenanceSettings(s.data)
	body, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (a *API) maintenanceSnapshot(w http.ResponseWriter, _ *http.Request) {
	settings := a.maintenance.Snapshot()
	a.maintenanceMu.Lock()
	running := a.maintenanceRunning
	a.maintenanceMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"settings":    settings,
		"running":     running,
		"serverCount": len(a.store.Snapshot().Servers),
	})
}

func (a *API) maintenanceUpdate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled              bool `json:"enabled"`
		KeepSuccessImages    int  `json:"keepSuccessImages"`
		IntervalHours        int  `json:"intervalHours"`
		CleanImageTar        bool `json:"cleanImageTar"`
		VacuumJournal        bool `json:"vacuumJournal"`
		KeepRecoveryPackages int  `json:"keepRecoveryPackages"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := a.maintenance.Update(func(s *MaintenanceSettings) {
		s.Enabled = input.Enabled
		s.KeepSuccessImages = input.KeepSuccessImages
		s.IntervalHours = input.IntervalHours
		s.CleanImageTar = input.CleanImageTar
		s.VacuumJournal = input.VacuumJournal
		s.KeepRecoveryPackages = input.KeepRecoveryPackages
	}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存自动清理设置失败: " + err.Error()})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		appendAudit(s, "maintenance.update", "system", "自动清理策略已更新", map[string]any{
			"enabled": input.Enabled, "keepSuccessImages": input.KeepSuccessImages, "intervalHours": input.IntervalHours,
		})
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "settings": a.maintenance.Snapshot()})
}

func (a *API) maintenanceRun(w http.ResponseWriter, r *http.Request) {
	settings := a.maintenance.Snapshot()
	trigger := "手动执行"
	result := a.runMaintenanceAll(trigger, settings)
	status := 200
	if result.Error != "" {
		status = 409 // 例如部署正在进行，本次跳过
	}
	writeJSON(w, status, result)
}

type MaintenanceRunResult struct {
	StartedAt    time.Time         `json:"startedAt"`
	FinishedAt   time.Time         `json:"finishedAt"`
	Trigger      string            `json:"trigger"`
	ReclaimedMB  int64             `json:"reclaimedMB"`
	RecoveryDone []string          `json:"recoveryRemoved,omitempty"`
	Nodes        []MaintenanceNode `json:"nodes"`
	Protected    int               `json:"protectedImages"`
	Error        string            `json:"error,omitempty"`
}

// runMaintenanceAll 对所有托管服务器执行一次清理（控制面所在机器走本地执行，其余走 SSH）。
func (a *API) runMaintenanceAll(trigger string, settings MaintenanceSettings) MaintenanceRunResult {
	started := time.Now()
	result := MaintenanceRunResult{StartedAt: started, Trigger: trigger, Nodes: []MaintenanceNode{}}
	a.maintenanceMu.Lock()
	if a.maintenanceRunning {
		a.maintenanceMu.Unlock()
		return MaintenanceRunResult{StartedAt: started, FinishedAt: time.Now(), Trigger: trigger, Error: "已有清理任务在运行", Nodes: []MaintenanceNode{}}
	}
	a.maintenanceRunning = true
	a.maintenanceMu.Unlock()
	defer func() {
		a.maintenanceMu.Lock()
		a.maintenanceRunning = false
		a.maintenanceMu.Unlock()
	}()

	// 有部署正在跑时不要动 buildah：正在构建的镜像和它的中间层不能被回收。
	a.deployMu.Lock()
	deploying := len(a.activeDeploys) > 0
	a.deployMu.Unlock()
	state := a.store.Snapshot()
	if !deploying {
		for _, app := range state.Apps {
			if app.Status == "deploying" {
				deploying = true
				break
			}
		}
	}
	if deploying {
		a.maintenanceMu.Lock()
		a.maintenanceRunning = false
		a.maintenanceMu.Unlock()
		note := "检测到正在进行的部署，本次跳过清理，等部署结束后再执行"
		_ = a.maintenance.Update(func(s *MaintenanceSettings) { s.LastStatus, s.LastTrigger = "skipped", trigger })
		return MaintenanceRunResult{StartedAt: started, FinishedAt: time.Now(), Trigger: trigger, Nodes: []MaintenanceNode{}, Error: note}
	}

	protectedTotal := 0
	logLines := []string{fmt.Sprintf("[%s] 开始自动清理（%s）", started.Format("2006-01-02 15:04:05 MST"), trigger)}

	for _, server := range state.Servers {
		protected, _ := protectedImages(state, server.ID, settings.KeepSuccessImages)
		node := a.runNodeMaintenance(server, protected, settings)
		protectedTotal += len(protected)
		result.ReclaimedMB += node.ReclaimedMB
		result.Nodes = append(result.Nodes, node)

		header := fmt.Sprintf("== %s (%s) ==", server.Name, server.Host)
		if node.Status == "ok" {
			header += fmt.Sprintf(" 磁盘 %d%% / 可用 %.1fG / 镜像 %d 个（删除 %d）/ 释放 %dMB",
				node.DiskPercent, node.AvailGB, node.ImagesTotal, node.ImagesDeleted, node.ReclaimedMB)
		} else {
			header += " 失败：" + node.Message
		}
		logLines = append(logLines, header)
		if node.Output != "" {
			logLines = append(logLines, node.Output)
		}
		logLines = append(logLines, "")
	}

	if settings.KeepRecoveryPackages > 0 {
		if removed, err := cleanupRecoveryPackages(recoveryRoot, settings.KeepRecoveryPackages); err != nil {
			logLines = append(logLines, "灾难恢复包清理失败："+err.Error())
		} else if len(removed) > 0 {
			result.RecoveryDone = removed
			logLines = append(logLines, "已清理旧灾难恢复包："+strings.Join(removed, "、"))
		}
	}

	result.FinishedAt = time.Now()
	result.Protected = protectedTotal
	logLines = append(logLines, fmt.Sprintf("完成，共释放约 %dMB，保护镜像 %d 个", result.ReclaimedMB, protectedTotal))

	status := "ok"
	failed := 0
	for _, node := range result.Nodes {
		if node.Status != "ok" {
			failed++
		}
	}
	if failed > 0 {
		status = "partial"
	}
	if len(result.Nodes) == 0 {
		result.Error = ""
	}

	logText := tailText(strings.Join(logLines, "\n"), 12000)
	finished := result.FinishedAt
	_ = a.maintenance.Update(func(s *MaintenanceSettings) {
		s.LastRunAt = &finished
		s.LastTrigger = trigger
		s.LastStatus = status
		s.LastReclaimedMB = result.ReclaimedMB
		s.LastLog = logText
		s.LastServers = result.Nodes
	})
	if result.RecoveryDone != nil {
		_ = a.store.mutate(func(s *State) error {
			appendAudit(s, "maintenance.recovery-cleanup", "system", "自动清理旧灾难恢复包", map[string]any{"removed": result.RecoveryDone})
			return nil
		})
	}
	_ = a.store.mutate(func(s *State) error {
		appendAudit(s, "maintenance.run", "system", "自动清理完成", map[string]any{
			"trigger": trigger, "reclaimedMB": result.ReclaimedMB, "protectedImages": protectedTotal, "failedServers": failed,
		})
		return nil
	})
	return result
}

// protectedImages 返回某台服务器上「绝不能删」的镜像：每个应用当前运行的镜像，
// 以及它最近 keep 次成功部署的镜像。以控制面记录为准，不受构建失败产生的 tag 干扰。
func protectedImages(state State, serverID string, keep int) ([]string, map[string]string) {
	if keep < 1 {
		keep = 1
	}
	seen := map[string]bool{}
	list := []string{}
	byApp := map[string]string{}
	add := func(image string) {
		image = strings.TrimSpace(image)
		if image == "" || seen[image] {
			return
		}
		seen[image] = true
		list = append(list, image)
	}
	for _, app := range state.Apps {
		if app.ServerID != serverID || app.ManagedMode == "adopted" {
			continue
		}
		add(app.Image)
		revisions := append([]DeploymentRevision(nil), app.Revisions...)
		sort.SliceStable(revisions, func(i, j int) bool { return revisions[i].DeployedAt.After(revisions[j].DeployedAt) })
		count := 0
		for _, revision := range revisions {
			if strings.TrimSpace(revision.Image) == "" {
				continue
			}
			add(revision.Image)
			count++
			if count >= keep {
				break
			}
		}
		byApp[app.Name] = app.Image
	}
	sort.Strings(list)
	return list, byApp
}

func (a *API) runNodeMaintenance(server Server, protected []string, settings MaintenanceSettings) MaintenanceNode {
	node := MaintenanceNode{ServerID: server.ID, Name: server.Name, Host: server.Host, Status: "ok", Protected: protected}
	script := buildMaintenanceScript()
	payload := base64.StdEncoding.EncodeToString([]byte(strings.Join(protected, "\n")))
	flag := func(value bool) string {
		if value {
			return "1"
		}
		return "0"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	command := fmt.Sprintf("printf '%%s' %s | base64 -d | bash -s -- '%s' '%s' '%s' '120'",
		base64.StdEncoding.EncodeToString([]byte(script)), payload, flag(settings.CleanImageTar), flag(settings.VacuumJournal))

	var output string
	var runErr error
	// 一律走 SSH（与部署同一条通道）：面板进程本身运行在 systemd 沙箱里
	// （ProtectSystem=strict，只放开 /var/lib/minipaas），直接调用 buildah 无法写
	// /var/lib/containers，镜像会一个都统计不到。SSH 会话不受这个沙箱限制。
	if key, keyErr := a.secrets.Decrypt(server.Credential); keyErr == nil {
		client := RemoteClient{Server: server, PrivateKey: key}
		output, runErr = client.run(ctx, command, 9*time.Minute)
	} else {
		runErr = keyErr
	}
	// 降级：连不上自己（或凭据失效）时，本机直接执行。buildah 仍可能不可用，
	// 但构建缓存与系统日志照样能回收，不至于完全没效果。
	if runErr != nil && isLocalServer(server) {
		cmd := exec.CommandContext(ctx, "bash", "-c", script, "minipaas-maintenance", payload, flag(settings.CleanImageTar), flag(settings.VacuumJournal), "120")
		raw, localErr := cmd.CombinedOutput()
		if strings.TrimSpace(string(raw)) != "" {
			output = string(raw)
			runErr = localErr
		}
	}
	node.Output = tailText(strings.TrimSpace(output), 4000)
	if runErr != nil && !strings.Contains(output, "MINIPAAS_MAINT") {
		node.Status, node.Message = "error", firstLine(runErr.Error()+" "+output)
		return node
	}
	total, deleted, diskPercent, availKB, beforeKB := parseMaintenanceOutput(output)
	node.ImagesTotal, node.ImagesDeleted, node.DiskPercent = total, deleted, diskPercent
	node.AvailGB = float64(availKB) / 1048576
	if beforeKB > 0 && availKB > beforeKB {
		node.ReclaimedMB = (availKB - beforeKB) / 1024
	}
	if runErr != nil {
		node.Status, node.Message = "error", firstLine(runErr.Error())
	}
	return node
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		value = value[:index]
	}
	if len(value) > 300 {
		value = value[:300]
	}
	return value
}

func parseMaintenanceOutput(output string) (total, deleted, diskPercent int, availKB, beforeKB int64) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "MINIPAAS_MAINT ") {
			continue
		}
		for _, field := range strings.Fields(strings.TrimPrefix(line, "MINIPAAS_MAINT ")) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			number, _ := strconv.ParseInt(value, 10, 64)
			switch key {
			case "total":
				total = int(number)
			case "deleted":
				deleted = int(number)
			case "disk_pct":
				diskPercent = int(number)
			case "avail_kb":
				availKB = number
			case "before_kb":
				beforeKB = number
			}
		}
	}
	return
}

// isLocalServer 判断托管服务器是否就是控制面所在机器：是则直接本地执行，
// 避免为了清理磁盘还要绕一圈 SSH（本机往往没有配置免密登录自己）。
func isLocalServer(server Server) bool {
	host := strings.ToLower(strings.TrimSpace(server.Host))
	if host == "" {
		return false
	}
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return true
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if network, ok := addr.(*net.IPNet); ok && network.IP.String() == host {
				return true
			}
		}
	}
	if name, err := os.Hostname(); err == nil && strings.EqualFold(name, host) {
		return true
	}
	return false
}

// buildMaintenanceScript 生成在目标服务器上执行的清理脚本。
//
//	$1 = 受保护镜像列表（base64，每行一个 image:tag）
//	$2 = 是否清理 image.tar
//	$3 = 是否压缩系统日志
//	$4 = image.tar 至少多久没被改动才删（分钟）
func buildMaintenanceScript() string {
	return `set -u
PROTECT_B64="${1:-}"
DO_TAR="${2:-1}"
DO_JOURNAL="${3:-1}"
TAR_MINUTES="${4:-120}"

protect=$(mktemp)
all=$(mktemp)
trap 'rm -f "$protect" "$all"' EXIT

# base64 解码后必须补一个换行，否则最后一条会和后面追加的运行中镜像粘成一行
{ printf '%s' "$PROTECT_B64" | base64 -d 2>/dev/null || true; printf '\n'; } | tr -d '\r' | sed '/^[[:space:]]*$/d' > "$protect"

# 正在运行的镜像也列入保护：即使控制面记录缺失也绝不删正在用的镜像
if command -v k3s >/dev/null 2>&1; then
  { k3s crictl ps -o json 2>/dev/null || true; } | grep -o '"imageRef"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' >> "$protect" || true
  { k3s kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true; } >> "$protect" || true
fi
sed -i 's|^docker\.io/||; s|@sha256:.*||' "$protect" 2>/dev/null || true
sed -i 's/^[[:space:]]*//; s/[[:space:]]*$//' "$protect" 2>/dev/null || true
sort -u "$protect" -o "$protect" 2>/dev/null || true

before_kb=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')
[ -n "${before_kb:-}" ] || before_kb=0

total=0
deleted=0
if command -v buildah >/dev/null 2>&1; then
  buildah images --format '{{.Name}}:{{.Tag}}' 2>/dev/null | grep -E '^localhost/minipaas/' | sort -u > "$all" || true
  while IFS= read -r img; do
    [ -z "$img" ] && continue
    case "$img" in *':<none>') continue ;; esac
    total=$((total+1))
    if grep -Fxq "$img" "$protect"; then
      continue
    fi
    if buildah rmi -f "$img" >/dev/null 2>&1; then
      echo "已删除旧镜像 $img"
      deleted=$((deleted+1))
    else
      echo "跳过 $img（仍被容器引用）"
    fi
  done < "$all"
fi

if [ "$DO_TAR" = "1" ]; then
  find /var/lib/minipaas/builds -maxdepth 2 -name image.tar -mmin +"$TAR_MINUTES" -print -delete 2>/dev/null | sed 's/^/已删除构建缓存 /' || true
fi

if [ "$DO_JOURNAL" = "1" ] && command -v journalctl >/dev/null 2>&1; then
  journalctl --vacuum-size=300M >/dev/null 2>&1 || true
fi

avail_kb=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')
[ -n "${avail_kb:-}" ] || avail_kb=0
disk_pct=$(df -P / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
[ -n "${disk_pct:-}" ] || disk_pct=0

echo "清理后：磁盘 ${disk_pct}%，可用 $((avail_kb/1024/1024))GB，镜像 ${total} 个，本次删除 ${deleted} 个"
printf 'MINIPAAS_MAINT total=%s deleted=%s disk_pct=%s avail_kb=%s before_kb=%s\n' "$total" "$deleted" "$disk_pct" "$avail_kb" "$before_kb"
`
}

// cleanupRecoveryPackages 只保留最近 keep 个灾难恢复包，指针 latest 指向的那份始终保留。
func cleanupRecoveryPackages(root string, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil
	}
	ids := []string{}
	for _, entry := range entries {
		if entry.IsDir() && recoveryPackagePattern.MatchString(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	if len(ids) <= keep {
		return nil, nil
	}
	latest := ""
	if target, linkErr := os.Readlink(filepath.Join(root, "latest")); linkErr == nil {
		latest = filepath.Base(filepath.Clean(target))
	}
	removed := []string{}
	for _, id := range ids[keep:] {
		if id == latest {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, id)); err != nil {
			return removed, err
		}
		removed = append(removed, id)
	}
	return removed, nil
}

// runAutoMaintenance 内置定时器：不需要 crontab，升级或换服务器部署后自动生效。
func (a *API) runAutoMaintenance() {
	time.Sleep(2 * time.Minute)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		settings := a.maintenance.Snapshot()
		if settings.Enabled {
			due := settings.LastRunAt == nil || time.Since(*settings.LastRunAt) >= time.Duration(settings.IntervalHours)*time.Hour
			if due {
				a.maintenanceMu.Lock()
				running := a.maintenanceRunning
				a.maintenanceMu.Unlock()
				if !running {
					a.runMaintenanceAll("定时任务", settings)
				}
			}
		}
		<-ticker.C
	}
}
