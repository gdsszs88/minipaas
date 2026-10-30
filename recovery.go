package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const recoveryRoot = "/root/independent-backups"

var recoveryPackagePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$`)

type RecoveryPackage struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"createdAt"`
	Size         int64     `json:"size"`
	Files        int       `json:"files"`
	Manifests    bool      `json:"manifests"`
	Databases    int       `json:"databases"`
	Images       bool      `json:"images"`
	ControlPlane bool      `json:"controlPlane"`
	Checksum     bool      `json:"checksum"`
}

type RecoveryOptions struct {
	PackageID    string `json:"packageId"`
	Server       bool   `json:"server"`
	Applications bool   `json:"applications"`
	Variables    bool   `json:"variables"`
	Databases    bool   `json:"databases"`
	Domains      bool   `json:"domains"`
	ControlPlane bool   `json:"controlPlane"`
	Confirm      string `json:"confirm"`
}

type RecoveryJob struct {
	ID         string          `json:"id"`
	PackageID  string          `json:"packageId"`
	Status     string          `json:"status"`
	Current    string          `json:"current,omitempty"`
	Progress   int             `json:"progress"`
	Log        []string        `json:"log"`
	Error      string          `json:"error,omitempty"`
	Options    RecoveryOptions `json:"options"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt time.Time       `json:"finishedAt,omitempty"`
}

func scanRecoveryPackages() ([]RecoveryPackage, error) {
	entries, err := os.ReadDir(recoveryRoot)
	if err != nil {
		return []RecoveryPackage{}, nil
	}
	items := []RecoveryPackage{}
	for _, entry := range entries {
		if !entry.IsDir() || !recoveryPackagePattern.MatchString(entry.Name()) {
			continue
		}
		root := filepath.Join(recoveryRoot, entry.Name())
		item := RecoveryPackage{ID: entry.Name()}
		if info, statErr := entry.Info(); statErr == nil {
			item.CreatedAt = info.ModTime()
		}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr == nil && info.Mode().IsRegular() {
				item.Size += info.Size()
				item.Files++
			}
			return nil
		})
		item.Manifests = fileExists(filepath.Join(root, "manifests", "cluster-resources.yaml"))
		item.Images = fileExists(filepath.Join(root, "images", "minipaas-managed-images.tar"))
		item.ControlPlane = fileExists(filepath.Join(root, "system", "minipaas-control-plane.tar.gz"))
		item.Checksum = fileExists(filepath.Join(root, "SHA256SUMS"))
		if db, readErr := os.ReadDir(filepath.Join(root, "databases")); readErr == nil {
			for _, f := range db {
				if !f.IsDir() {
					item.Databases++
				}
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return items, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func checksumRelativePath(saved string) string {
	clean := filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(saved), "*"))
	for _, marker := range []string{"/databases/", "/manifests/", "/system/", "/images/"} {
		if index := strings.Index(clean, marker); index >= 0 {
			return strings.TrimPrefix(clean[index:], "/")
		}
	}
	return strings.TrimPrefix(clean, "./")
}

func verifyRecoveryPackage(root string) (string, error) {
	file, err := os.Open(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner, checked, logs := bufio.NewScanner(file), 0, []string{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		relative := checksumRelativePath(fields[1])
		if relative == "SHA256SUMS" || strings.Contains(relative, "..") {
			continue
		}
		content, openErr := os.Open(filepath.Join(root, filepath.FromSlash(relative)))
		if openErr != nil {
			return strings.Join(logs, "\n"), fmt.Errorf("缺少文件 %s", relative)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, content)
		_ = content.Close()
		if copyErr != nil {
			return strings.Join(logs, "\n"), copyErr
		}
		if actual := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(actual, fields[0]) {
			return strings.Join(logs, "\n"), fmt.Errorf("文件校验不一致: %s", relative)
		}
		checked++
		logs = append(logs, relative+": OK")
	}
	if err := scanner.Err(); err != nil {
		return strings.Join(logs, "\n"), err
	}
	if checked == 0 {
		return "", fmt.Errorf("校验文件中没有有效条目")
	}
	return fmt.Sprintf("已校验 %d 个文件\n%s", checked, strings.Join(logs, "\n")), nil
}

func (a *API) recoveryPackages(w http.ResponseWriter, _ *http.Request) {
	items, err := scanRecoveryPackages()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"packages": items, "root": recoveryRoot})
}

func (a *API) recoveryVerify(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !recoveryPackagePattern.MatchString(id) {
		writeJSON(w, 400, map[string]string{"error": "备份包名称不安全"})
		return
	}
	root := filepath.Join(recoveryRoot, id)
	out, err := verifyRecoveryPackage(root)
	if err != nil {
		writeJSON(w, 422, map[string]any{"error": "备份校验失败，禁止恢复: " + err.Error(), "output": tailText(out, 12000)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": tailText(out, 12000)})
}

func (a *API) recoveryUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "请选择备份压缩包"})
		return
	}
	part, err := reader.NextPart()
	if err != nil || part.FormName() != "archive" {
		writeJSON(w, 400, map[string]string{"error": "没有收到备份文件"})
		return
	}
	name, kind := strings.ToLower(filepath.Base(part.FileName())), ""
	if strings.HasSuffix(name, ".zip") {
		kind = "zip"
	} else if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
		kind = "tgz"
	}
	if kind == "" {
		writeJSON(w, 400, map[string]string{"error": "仅支持 .zip、.tar.gz 或 .tgz"})
		return
	}
	id := time.Now().Format("2006-01-02_15-04-05")
	archive, stage := filepath.Join(recoveryRoot, ".upload-"+id+"."+kind), filepath.Join(recoveryRoot, ".extract-"+id)
	_ = os.MkdirAll(recoveryRoot, 0700)
	out, createErr := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if createErr != nil {
		writeJSON(w, 500, map[string]string{"error": createErr.Error()})
		return
	}
	_, copyErr := io.Copy(out, part)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(archive)
		writeJSON(w, 500, map[string]string{"error": "上传备份失败"})
		return
	}
	defer os.Remove(archive)
	_ = os.MkdirAll(stage, 0700)
	defer os.RemoveAll(stage)
	listArgs, extractArgs := []string{}, []string{}
	if kind == "zip" {
		listArgs = []string{"unzip", "-Z1", archive}
		extractArgs = []string{"unzip", "-q", archive, "-d", stage}
	} else {
		listArgs = []string{"tar", "-tzf", archive}
		extractArgs = []string{"tar", "-xzf", archive, "-C", stage}
	}
	listed, listErr := exec.Command(listArgs[0], listArgs[1:]...).CombinedOutput()
	if listErr != nil {
		writeJSON(w, 422, map[string]string{"error": "无法读取备份压缩包"})
		return
	}
	for _, item := range strings.Split(string(listed), "\n") {
		clean := filepath.ToSlash(strings.TrimSpace(item))
		if strings.HasPrefix(clean, "/") || strings.Contains("/"+clean+"/", "/../") {
			writeJSON(w, 422, map[string]string{"error": "压缩包包含不安全路径"})
			return
		}
	}
	if extracted, extractErr := exec.Command(extractArgs[0], extractArgs[1:]...).CombinedOutput(); extractErr != nil {
		writeJSON(w, 422, map[string]string{"error": "解压失败: " + tailText(string(extracted), 1200)})
		return
	}
	source := stage
	if !fileExists(filepath.Join(source, "SHA256SUMS")) {
		entries, _ := os.ReadDir(stage)
		if len(entries) == 1 && entries[0].IsDir() {
			source = filepath.Join(stage, entries[0].Name())
		}
	}
	if !fileExists(filepath.Join(source, "SHA256SUMS")) {
		writeJSON(w, 422, map[string]string{"error": "压缩包中找不到 SHA256SUMS"})
		return
	}
	if _, verifyErr := verifyRecoveryPackage(source); verifyErr != nil {
		writeJSON(w, 422, map[string]string{"error": "上传后校验失败: " + verifyErr.Error()})
		return
	}
	destination := filepath.Join(recoveryRoot, id)
	if renameErr := os.Rename(source, destination); renameErr != nil {
		writeJSON(w, 500, map[string]string{"error": "保存备份包失败: " + renameErr.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "id": id})
}

func (a *API) recoveryStart(w http.ResponseWriter, r *http.Request) {
	var input RecoveryOptions
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if !recoveryPackagePattern.MatchString(input.PackageID) || input.Confirm != "恢复 "+input.PackageID {
		writeJSON(w, 400, map[string]string{"error": "恢复确认文字不正确"})
		return
	}
	if !input.Server && !input.Applications && !input.Variables && !input.Databases && !input.Domains && !input.ControlPlane {
		writeJSON(w, 400, map[string]string{"error": "至少选择一个恢复项目"})
		return
	}
	if _, err := os.Stat(filepath.Join(recoveryRoot, input.PackageID, "SHA256SUMS")); err != nil {
		writeJSON(w, 404, map[string]string{"error": "找不到备份包或校验文件"})
		return
	}
	job := &RecoveryJob{ID: newID("recovery"), PackageID: input.PackageID, Status: "running", Current: "准备恢复", Progress: 1, Options: input, StartedAt: time.Now(), Log: []string{"恢复任务已创建"}}
	a.recoveryMu.Lock()
	a.recoveryJobs[job.ID] = job
	a.recoveryMu.Unlock()
	go a.runRecovery(job.ID)
	writeJSON(w, 202, job)
}

func (a *API) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	a.recoveryMu.RLock()
	job, ok := a.recoveryJobs[r.PathValue("id")]
	if ok {
		copy := *job
		copy.Log = append([]string(nil), job.Log...)
		job = &copy
	}
	a.recoveryMu.RUnlock()
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "恢复任务不存在"})
		return
	}
	writeJSON(w, 200, job)
}

func (a *API) updateRecovery(id, current string, progress int, line string) {
	a.recoveryMu.Lock()
	defer a.recoveryMu.Unlock()
	if job := a.recoveryJobs[id]; job != nil {
		job.Current, job.Progress = current, progress
		if line != "" {
			job.Log = append(job.Log, line)
		}
	}
}

func (a *API) recoveryCommand(id, root, current string, progress int, script string) error {
	a.updateRecovery(id, current, progress, "开始："+current)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-lc", script, "recovery-step", root)
	out, err := cmd.CombinedOutput()
	a.updateRecovery(id, current, progress, tailText(strings.TrimSpace(string(out)), 8000))
	return err
}

func (a *API) runRecovery(id string) {
	a.recoveryMu.RLock()
	job := a.recoveryJobs[id]
	options := job.Options
	a.recoveryMu.RUnlock()
	root := filepath.Join(recoveryRoot, options.PackageID)
	fail := func(step string, err error) {
		a.recoveryMu.Lock()
		if job := a.recoveryJobs[id]; job != nil {
			job.Status, job.Error, job.Current, job.FinishedAt = "failed", step+": "+err.Error(), "恢复失败", time.Now()
		}
		a.recoveryMu.Unlock()
	}
	a.updateRecovery(id, "校验备份完整性", 8, "开始：校验备份完整性")
	verifyOutput, verifyErr := verifyRecoveryPackage(root)
	a.updateRecovery(id, "校验备份完整性", 8, tailText(verifyOutput, 8000))
	if verifyErr != nil {
		fail("备份校验失败", verifyErr)
		return
	}
	if err := a.recoveryCommand(id, root, "创建恢复前安全备份", 18, `systemctl start independent-backup.service`); err != nil {
		fail("安全备份失败", err)
		return
	}
	if options.Server {
		script := `set -e
test -x /usr/local/bin/k3s
cp -a "$1/system/independent-deploy.d" /etc/ 2>/dev/null || true
for f in deploy-all-sites independent-k3s-firewall; do test ! -f "$1/system/$f" || install -m 0755 "$1/system/$f" /usr/local/sbin/$f; done
for f in "$1"/system/*.service "$1"/system/*.timer; do test ! -f "$f" || cp -a "$f" /etc/systemd/system/; done
systemctl daemon-reload`
		if err := a.recoveryCommand(id, root, "恢复服务器运行环境", 30, script); err != nil {
			fail("服务器环境恢复失败", err)
			return
		}
	}
	if options.Applications && fileExists(filepath.Join(root, "images", "minipaas-managed-images.tar")) {
		if err := a.recoveryCommand(id, root, "导入网站镜像", 42, `k3s ctr -n k8s.io images import "$1/images/minipaas-managed-images.tar"`); err != nil {
			fail("镜像恢复失败", err)
			return
		}
	}
	if options.Applications || options.Variables || options.Domains || options.Databases {
		if err := a.recoveryCommand(id, root, "恢复网站、变量与域名清单", 58, `k3s kubectl apply -f "$1/manifests/cluster-resources.yaml"`); err != nil {
			fail("Kubernetes 清单恢复失败", err)
			return
		}
		_ = a.recoveryCommand(id, root, "等待网站与数据库启动", 68, `sleep 8; k3s kubectl get pods -A -o wide`)
	}
	if options.Databases {
		script := `set -e
for sql in "$1"/databases/*-postgres.sql; do
  test -f "$sql" || continue
  base=$(basename "$sql"); ns=${base%%-database-*}; test "$ns" != "$base" || ns=${base%%-service-*}
  pod=$(k3s kubectl -n "$ns" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' | awk -F'|' '$2 ~ /(^|\/)postgres:/ {print $1; exit}')
  test -n "$pod" || { echo "未找到 $ns 的 PostgreSQL Pod"; exit 1; }
  k3s kubectl -n "$ns" exec -i "$pod" -- sh -lc 'psql -v ON_ERROR_STOP=0 -U "${POSTGRES_USER:-postgres}"' < "$sql"
done
for sql in "$1"/databases/*-mysql.sql; do
  test -f "$sql" || continue
  base=$(basename "$sql"); ns=${base%%-database-*}; test "$ns" != "$base" || ns=${base%%-service-*}
  pod=$(k3s kubectl -n "$ns" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' | awk -F'|' '$2 ~ /(^|\/)mysql:/ {print $1; exit}')
  test -n "$pod" || { echo "未找到 $ns 的 MySQL Pod"; exit 1; }
  k3s kubectl -n "$ns" exec -i "$pod" -- sh -lc 'mysql -u"${MYSQL_USER:-root}" -p"${MYSQL_PASSWORD:-$MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}"' < "$sql"
done
for rdb in "$1"/databases/*-redis.rdb; do
  test -f "$rdb" || continue
  base=$(basename "$rdb"); ns=${base%%-database-*}; test "$ns" != "$base" || ns=${base%%-service-*}
  pod=$(k3s kubectl -n "$ns" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' | awk -F'|' '$2 ~ /(^|\/)redis:/ {print $1; exit}')
  test -n "$pod" || { echo "未找到 $ns 的 Redis Pod"; exit 1; }
  k3s kubectl cp "$rdb" "$ns/$pod:/data/dump.rdb"
  k3s kubectl -n "$ns" delete pod "$pod" --wait=false
done`
		if err := a.recoveryCommand(id, root, "恢复数据库数据", 82, script); err != nil {
			fail("数据库恢复失败", err)
			return
		}
	}
	if options.ControlPlane {
		script := `set -e
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
tar -xzf "$1/system/minipaas-control-plane.tar.gz" -C "$tmp"
test -f "$tmp/var/lib/minipaas/master.key"
cp -a "$tmp/var/lib/minipaas/." /var/lib/minipaas/
systemd-run --unit=minipaas-recovery-restart --on-active=5s /bin/systemctl restart minipaas`
		if err := a.recoveryCommand(id, root, "恢复面板设置并安排重启", 94, script); err != nil {
			fail("控制面恢复失败", err)
			return
		}
	}
	a.recoveryMu.Lock()
	if job := a.recoveryJobs[id]; job != nil {
		job.Status, job.Current, job.Progress, job.FinishedAt = "completed", "恢复完成", 100, time.Now()
		job.Log = append(job.Log, "所有选定项目已恢复")
	}
	a.recoveryMu.Unlock()
	if !options.ControlPlane {
		_ = a.store.mutate(func(s *State) error {
			appendAudit(s, "recovery.completed", options.PackageID, "灾难恢复任务已完成", map[string]any{"jobId": id})
			return nil
		})
	}
}
