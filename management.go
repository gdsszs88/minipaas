package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type deleteRequest struct {
	ConfirmName string `json:"confirmName"`
	DeleteData  bool   `json:"deleteData,omitempty"`
}

func (a *API) serverUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input struct {
		Name, Host, User, Description, AuthType, PrivateKey, Password string
		Port                                                          int
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	input.Name, input.Host, input.User = strings.TrimSpace(input.Name), strings.TrimSpace(input.Host), strings.TrimSpace(input.User)
	if input.User == "" {
		input.User = "root"
	}
	if input.Port == 0 {
		input.Port = 22
	}
	if input.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "服务器名称不能为空"})
		return
	}
	if err := validateSSHAddress(input.Host, input.Port, input.User); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if input.AuthType == "" {
		input.AuthType = "privateKey"
	}
	if input.AuthType != "privateKey" && input.AuthType != "password" {
		writeJSON(w, 400, map[string]string{"error": "SSH 登录方式不正确"})
		return
	}
	newCredential := ""
	plainCredential := input.PrivateKey
	if input.AuthType == "password" {
		plainCredential = input.Password
	}
	if plainCredential != "" {
		encrypted, err := a.secrets.Encrypt([]byte(plainCredential))
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "无法加密私钥"})
			return
		}
		newCredential = encrypted
	}
	found := false
	err := a.store.mutate(func(state *State) error {
		for i := range state.Servers {
			if state.Servers[i].ID != id {
				continue
			}
			found = true
			if state.Servers[i].AuthType != input.AuthType && newCredential == "" {
				return errors.New("切换 SSH 登录方式时必须填写新的登录凭据")
			}
			connectionChanged := state.Servers[i].Host != input.Host || state.Servers[i].Port != input.Port || state.Servers[i].User != input.User || state.Servers[i].AuthType != input.AuthType || newCredential != ""
			state.Servers[i].Name, state.Servers[i].Host, state.Servers[i].Port, state.Servers[i].User, state.Servers[i].Description = input.Name, input.Host, input.Port, input.User, input.Description
			state.Servers[i].AuthType = input.AuthType
			if newCredential != "" {
				state.Servers[i].Credential = newCredential
			}
			if connectionChanged {
				state.Servers[i].Status, state.Servers[i].HostKeyFingerprint = "pending", ""
			}
		}
		if !found {
			return errors.New("服务器不存在")
		}
		appendAudit(state, "server.update", id, "已更新服务器 "+input.Name, nil)
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) serverDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input deleteRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	state := a.store.Snapshot()
	var target Server
	found := false
	for _, item := range state.Servers {
		if item.ID == id {
			target, found = item, true
			break
		}
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "服务器不存在"})
		return
	}
	if input.ConfirmName != target.Name {
		writeJSON(w, 400, map[string]string{"error": "确认名称不匹配"})
		return
	}
	for _, app := range state.Apps {
		if app.ServerID == id {
			writeJSON(w, 409, map[string]string{"error": "请先删除该服务器上的应用"})
			return
		}
	}
	for _, database := range state.Databases {
		if database.ServerID == id {
			writeJSON(w, 409, map[string]string{"error": "请先删除该服务器上的数据库"})
			return
		}
	}
	_ = a.store.mutate(func(s *State) error {
		filtered := s.Servers[:0]
		for _, item := range s.Servers {
			if item.ID != id {
				filtered = append(filtered, item)
			}
		}
		s.Servers = filtered
		appendAudit(s, "server.delete", id, "已删除服务器记录 "+target.Name, nil)
		return nil
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) appDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input deleteRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	app, server, err := a.findAppAndServer(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if input.ConfirmName != app.Name {
		writeJSON(w, 400, map[string]string{"error": "确认名称不匹配"})
		return
	}
	if app.ManagedMode == "adopted" {
		_ = a.store.mutate(func(s *State) error {
			filtered := s.Apps[:0]
			for _, item := range s.Apps {
				if item.ID != id {
					filtered = append(filtered, item)
				}
			}
			s.Apps = filtered
			appendAudit(s, "app.detach", id, "已从面板移除接管记录，K3s 服务未删除："+app.Name, nil)
			return nil
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
	script := fmt.Sprintf(`set -euo pipefail
k3s kubectl -n minipaas-apps delete deployment %s --ignore-not-found
k3s kubectl -n minipaas-apps delete service %s --ignore-not-found
k3s kubectl -n minipaas-apps delete secret %s-env --ignore-not-found
rm -rf -- '/var/lib/minipaas/builds/%s' '/var/lib/minipaas/uploads/%s'
target=$(printf '%%s' '%s' | base64 -d)
if k3s kubectl -n default get configmap independent-caddy-config >/dev/null 2>&1; then
  file=/tmp/Caddyfile-minipaas-delete
  k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}' > "$file"
  python3 - "$file" "$file.new" "$target" <<'PY'
import sys
source, output, target = sys.argv[1:]
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
            if target not in text:
                result.append(text)
            current = []
        continue
    result.append(line)
if current and target not in ''.join(current):
    result.extend(current)
open(output, 'w', encoding='utf-8').write(''.join(result))
PY
  if ! cmp -s "$file" "$file.new"; then k3s kubectl -n default create configmap independent-caddy-config --from-file=Caddyfile="$file.new" --dry-run=client -o yaml | k3s kubectl apply -f -; k3s kubectl -n default rollout restart daemonset independent-caddy; fi
fi
`, name, name, name, app.ID, app.ID, shellB64(name+".minipaas-apps.svc.cluster.local:"+strconv.Itoa(app.Port)))
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if output, runErr := client.run(ctx, script, 4*time.Minute); runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "远程清理失败", "output": tailText(output, 6000)})
		return
	}
	uploadRoot := filepath.Join(a.dataDir, "uploads", app.ID)
	if strings.HasPrefix(filepath.Clean(uploadRoot), filepath.Clean(filepath.Join(a.dataDir, "uploads"))+string(os.PathSeparator)) {
		_ = os.RemoveAll(uploadRoot)
	}
	_ = a.store.mutate(func(s *State) error {
		filtered := s.Apps[:0]
		for _, item := range s.Apps {
			if item.ID != id {
				filtered = append(filtered, item)
			}
		}
		s.Apps = filtered
		appendAudit(s, "app.delete", id, "已删除应用 "+app.Name, nil)
		return nil
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) databaseUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input Database
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if input.Name == "" || input.ServerID == "" || input.StorageGB < 1 {
		writeJSON(w, 400, map[string]string{"error": "数据库配置不完整"})
		return
	}
	err := a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID != id {
				continue
			}
			if s.Databases[i].Status == "running" {
				return errors.New("运行中的数据库不能改名或切换引擎；请新建数据库迁移数据")
			}
			input.ID, input.Status, input.CreatedAt = s.Databases[i].ID, s.Databases[i].Status, s.Databases[i].CreatedAt
			s.Databases[i] = input
			appendAudit(s, "database.update", id, "已更新数据库 "+input.Name, nil)
			return nil
		}
		return errors.New("数据库不存在")
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) databaseDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input deleteRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	state := a.store.Snapshot()
	var database Database
	found := false
	for _, item := range state.Databases {
		if item.ID == id {
			database, found = item, true
			break
		}
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "数据库不存在"})
		return
	}
	if input.ConfirmName != database.Name || !input.DeleteData {
		writeJSON(w, 400, map[string]string{"error": "必须确认名称并明确永久删除数据"})
		return
	}
	if database.ManagedMode == "adopted" {
		_ = a.store.mutate(func(s *State) error {
			filtered := s.Databases[:0]
			for _, item := range s.Databases {
				if item.ID != id {
					filtered = append(filtered, item)
				}
			}
			s.Databases = filtered
			appendAudit(s, "database.detach", id, "已从面板移除数据库记录，数据卷未删除："+database.Name, nil)
			return nil
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var server Server
	for _, item := range state.Servers {
		if item.ID == database.ServerID {
			server = item
			break
		}
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	name := "db-" + kubeName(database.Name) + "-" + idSuffix(database.ID)
	script := fmt.Sprintf(`set -euo pipefail
k3s kubectl -n minipaas-data delete statefulset %s --ignore-not-found
k3s kubectl -n minipaas-data delete service %s --ignore-not-found
k3s kubectl -n minipaas-data delete secret %s-auth --ignore-not-found
k3s kubectl -n minipaas-data delete pvc data-%s-0 --ignore-not-found
`, name, name, name, name)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if output, runErr := client.run(ctx, script, 4*time.Minute); runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "数据库删除失败", "output": tailText(output, 6000)})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		filtered := s.Databases[:0]
		for _, item := range s.Databases {
			if item.ID != id {
				filtered = append(filtered, item)
			}
		}
		s.Databases = filtered
		appendAudit(s, "database.delete", id, "已永久删除数据库 "+database.Name, nil)
		return nil
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func idSuffix(id string) string {
	parts := strings.SplitN(id, "_", 2)
	value := parts[len(parts)-1]
	if len(value) > 6 {
		return value[:6]
	}
	return value
}
