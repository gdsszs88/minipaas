package main

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var kubeResourcePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

func (a *API) databaseAndServer(id string) (Database, Server, error) {
	state := a.store.Snapshot()
	var database Database
	for _, item := range state.Databases {
		if item.ID == id {
			database = item
			break
		}
	}
	if database.ID == "" {
		return Database{}, Server{}, fmt.Errorf("数据库不存在")
	}
	for _, server := range state.Servers {
		if server.ID == database.ServerID {
			return database, server, nil
		}
	}
	return Database{}, Server{}, fmt.Errorf("目标服务器不存在")
}

func databaseWorkload(database Database) (string, string, error) {
	if database.Engine != "postgresql" && database.Engine != "postgres" {
		return "", "", fmt.Errorf("当前可视化备份仅支持 PostgreSQL")
	}
	if database.ManagedMode == "adopted" {
		if !kubeResourcePattern.MatchString(database.Namespace) || !kubeResourcePattern.MatchString(database.Workload) {
			return "", "", fmt.Errorf("数据库工作负载标识不安全")
		}
		return database.Namespace, "deployment/" + database.Workload, nil
	}
	return "minipaas-data", "statefulset/db-" + kubeName(database.Name) + "-" + idSuffix(database.ID), nil
}

func backupSafeView(items []DatabaseBackup) []DatabaseBackup {
	out := append([]DatabaseBackup(nil), items...)
	for i := range out {
		out[i].RemotePath = ""
	}
	return out
}

func (a *API) databaseBackups(w http.ResponseWriter, r *http.Request) {
	database, _, err := a.databaseAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"database": database.Name, "engine": database.Engine, "backups": backupSafeView(database.Backups)})
}

func (a *API) createDatabaseBackup(ctx context.Context, database Database, server Server, reason string) (DatabaseBackup, error) {
	namespace, workload, err := databaseWorkload(database)
	if err != nil {
		return DatabaseBackup{}, err
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		return DatabaseBackup{}, fmt.Errorf("无法读取服务器凭据")
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	filename := kubeName(database.Name) + "-" + stamp + ".sql.gz"
	remotePath := "/var/lib/minipaas/database-backups/" + database.ID + "/" + filename
	script := fmt.Sprintf(`set -euo pipefail
file=$(printf '%%s' '%s' | base64 -d)
install -d -m 700 "$(dirname "$file")"
k3s kubectl -n %s exec %s -- sh -lc 'pg_dump --clean --if-exists --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip -9 > "$file"
chmod 600 "$file"
printf 'MINIPAAS_BACKUP|%%s|%%s\n' "$(stat -c %%s "$file")" "$file"
`, shellB64(remotePath), namespace, workload)
	client := RemoteClient{Server: server, PrivateKey: key}
	out, runErr := client.run(ctx, script, 20*time.Minute)
	if runErr != nil {
		return DatabaseBackup{}, fmt.Errorf("备份失败: %v (%s)", runErr, tailText(out, 2000))
	}
	line := ""
	for _, candidate := range strings.Split(out, "\n") {
		if strings.HasPrefix(candidate, "MINIPAAS_BACKUP|") {
			line = candidate
		}
	}
	parts := strings.SplitN(line, "|", 3)
	if len(parts) != 3 {
		return DatabaseBackup{}, fmt.Errorf("备份完成但未能读取文件信息")
	}
	size, _ := strconv.ParseInt(parts[1], 10, 64)
	return DatabaseBackup{ID: newID("backup"), Filename: filename, RemotePath: parts[2], Size: size, CreatedAt: time.Now(), Reason: reason}, nil
}

func (a *API) databaseBackupCreate(w http.ResponseWriter, r *http.Request) {
	database, server, err := a.databaseAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 22*time.Minute)
	defer cancel()
	backup, err := a.createDatabaseBackup(ctx, database, server, "手动备份")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID == database.ID {
				s.Databases[i].Backups = append(s.Databases[i].Backups, backup)
			}
		}
		appendAudit(s, "database.backup", database.ID, "数据库 "+database.Name+" 备份成功", map[string]any{"size": backup.Size})
		return nil
	})
	backup.RemotePath = ""
	writeJSON(w, 201, backup)
}

func findBackup(database Database, backupID string) (DatabaseBackup, bool) {
	for _, item := range database.Backups {
		if item.ID == backupID {
			return item, true
		}
	}
	return DatabaseBackup{}, false
}

func validBackupPath(databaseID, path string) bool {
	root := filepath.Clean("/var/lib/minipaas/database-backups/" + databaseID)
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, root+string(filepath.Separator))
}

func (a *API) databaseBackupDownload(w http.ResponseWriter, r *http.Request) {
	database, server, err := a.databaseAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	backup, ok := findBackup(database, r.PathValue("backupId"))
	if !ok || !validBackupPath(database.ID, backup.RemotePath) {
		writeJSON(w, 404, map[string]string{"error": "备份不存在"})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(backup.Filename, `"`, "")+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(backup.Size, 10))
	client := RemoteClient{Server: server, PrivateKey: key}
	_ = client.Download(r.Context(), backup.RemotePath, w)
}

func (a *API) databaseBackupRestore(w http.ResponseWriter, r *http.Request) {
	database, server, err := a.databaseAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var input struct {
		ConfirmName string `json:"confirmName"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if input.ConfirmName != database.Name {
		writeJSON(w, 400, map[string]string{"error": "数据库名称确认不匹配"})
		return
	}
	backup, ok := findBackup(database, r.PathValue("backupId"))
	if !ok || !validBackupPath(database.ID, backup.RemotePath) {
		writeJSON(w, 404, map[string]string{"error": "备份不存在"})
		return
	}
	namespace, workload, err := databaseWorkload(database)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Minute)
	defer cancel()
	safety, err := a.createDatabaseBackup(ctx, database, server, "恢复前自动备份")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "恢复已取消：无法创建恢复前安全备份；" + err.Error()})
		return
	}
	script := fmt.Sprintf(`set -euo pipefail
file=$(printf '%%s' '%s' | base64 -d)
test -s "$file"
gzip -dc "$file" | k3s kubectl -n %s exec -i %s -- sh -lc 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"'
`, shellB64(backup.RemotePath), namespace, workload)
	client := RemoteClient{Server: server, PrivateKey: key}
	out, runErr := client.run(ctx, script, 22*time.Minute)
	if runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "恢复失败，可使用自动安全备份重试", "output": tailText(out, 3000)})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID == database.ID {
				s.Databases[i].Backups = append(s.Databases[i].Backups, safety)
			}
		}
		appendAudit(s, "database.restore", database.ID, "数据库 "+database.Name+" 已从备份恢复", map[string]any{"backup": backup.Filename})
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "safetyBackup": map[string]any{"id": safety.ID, "filename": safety.Filename, "size": safety.Size}, "output": tailText(out, 2000)})
}
