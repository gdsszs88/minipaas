package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var databaseTablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *API) databaseProvision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	var server Server
	serverFound := false
	for _, item := range state.Servers {
		if item.ID == database.ServerID {
			server, serverFound = item, true
			break
		}
	}
	if !serverFound {
		writeJSON(w, 400, map[string]string{"error": "目标服务器不存在"})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	password := ""
	if database.PasswordCipher != "" {
		plain, decryptErr := a.secrets.Decrypt(database.PasswordCipher)
		if decryptErr == nil {
			password = string(plain)
		}
	}
	if password == "" {
		password = randomPassword()
	}
	manifest, details, err := databaseManifest(database, password)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ciphertext, err := a.secrets.Encrypt([]byte(password))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法保存数据库密码"})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID == id {
				s.Databases[i].Status = "provisioning"
			}
		}
		return nil
	})
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Minute)
	defer cancel()
	name := details["resourceName"]
	script := fmt.Sprintf(`set -euo pipefail
k3s kubectl create namespace minipaas-data --dry-run=client -o yaml | k3s kubectl apply -f -
printf '%%s' '%s' | base64 -d | k3s kubectl apply -f -
k3s kubectl -n minipaas-data rollout status statefulset/%s --timeout=360s
k3s kubectl -n minipaas-data get statefulset,service,pvc -l app.kubernetes.io/name=%s -o wide
`, shellB64(string(manifest)), name, name)
	output, runErr := client.run(ctx, script, 10*time.Minute)
	if runErr != nil {
		_ = a.store.mutate(func(s *State) error {
			for i := range s.Databases {
				if s.Databases[i].ID == id {
					s.Databases[i].Status = "failed"
				}
			}
			appendAudit(s, "database.provision.failed", id, "数据库部署失败", nil)
			return nil
		})
		writeJSON(w, 502, map[string]string{"error": "数据库部署失败", "output": tailText(output, 12000)})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID != id {
				continue
			}
			s.Databases[i].Status, s.Databases[i].PasswordCipher = "running", ciphertext
			s.Databases[i].Username, s.Databases[i].DatabaseName, s.Databases[i].Host = details["username"], details["database"], details["host"]
			s.Databases[i].Port, _ = strconv.Atoi(details["port"])
		}
		appendAudit(s, "database.provision", id, "数据库 "+database.Name+" 部署成功", nil)
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "engine": database.Engine, "host": details["host"], "port": details["port"], "username": details["username"], "password": password, "database": details["database"], "url": connectionURL(database.Engine, details["username"], password, details["host"], details["port"], details["database"]), "output": tailText(output, 6000)})
}

func databaseManifest(database Database, password string) ([]byte, map[string]string, error) {
	engine := strings.ToLower(database.Engine)
	name := "db-" + kubeName(database.Name) + "-" + idSuffix(database.ID)
	version, port, image, mountPath := database.Version, 0, "", ""
	username, dbName := "minipaas", kubeName(database.Name)
	secretData := map[string]string{}
	env := []any{}
	args := []any(nil)
	switch engine {
	case "postgresql", "postgres":
		engine = "postgresql"
		if version == "" {
			version = "16"
		}
		port, image, mountPath = 5432, "postgres:"+version+"-alpine", "/var/lib/postgresql/data"
		secretData = map[string]string{"POSTGRES_USER": username, "POSTGRES_PASSWORD": password, "POSTGRES_DB": dbName}
	case "mysql":
		if version == "" {
			version = "8.4"
		}
		port, image, mountPath = 3306, "mysql:"+version, "/var/lib/mysql"
		secretData = map[string]string{"MYSQL_ROOT_PASSWORD": randomPassword(), "MYSQL_DATABASE": dbName, "MYSQL_USER": username, "MYSQL_PASSWORD": password}
	case "redis":
		if version == "" {
			version = "7"
		}
		port, image, mountPath, username, dbName = 6379, "redis:"+version+"-alpine", "/data", "default", "0"
		secretData = map[string]string{"REDIS_PASSWORD": password}
		args = []any{"redis-server", "--appendonly", "yes", "--requirepass", "$(REDIS_PASSWORD)"}
	default:
		return nil, nil, errors.New("暂不支持该数据库类型")
	}
	for key := range secretData {
		env = append(env, map[string]any{"name": key, "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": name + "-auth", "key": key}}})
	}
	labels := map[string]any{"app.kubernetes.io/name": name, "app.kubernetes.io/managed-by": "minipaas"}
	container := map[string]any{"name": engine, "image": image, "ports": []any{map[string]any{"name": "database", "containerPort": port}}, "env": env, "volumeMounts": []any{map[string]any{"name": "data", "mountPath": mountPath}}, "resources": map[string]any{"requests": map[string]any{"cpu": "25m", "memory": "128Mi"}, "limits": map[string]any{"memory": "1Gi"}}}
	if args != nil {
		container["args"] = args
	}
	secret := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name + "-auth", "namespace": "minipaas-data"}, "type": "Opaque", "stringData": secretData}
	service := map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": name, "namespace": "minipaas-data", "labels": labels}, "spec": map[string]any{"clusterIP": "None", "selector": labels, "ports": []any{map[string]any{"name": "database", "port": port, "targetPort": "database"}}}}
	statefulSet := map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": map[string]any{"name": name, "namespace": "minipaas-data", "labels": labels}, "spec": map[string]any{"serviceName": name, "replicas": 1, "selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{container}}}, "volumeClaimTemplates": []any{map[string]any{"metadata": map[string]any{"name": "data"}, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}, "resources": map[string]any{"requests": map[string]any{"storage": fmt.Sprintf("%dGi", database.StorageGB)}}}}}}}
	manifest := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{secret, service, statefulSet}}
	b, err := json.Marshal(manifest)
	details := map[string]string{"resourceName": name, "username": username, "database": dbName, "host": name + ".minipaas-data.svc.cluster.local", "port": strconv.Itoa(port)}
	return b, details, err
}

func connectionURL(engine, username, password, host, port, database string) string {
	u := &url.URL{Scheme: engine, User: url.UserPassword(username, password), Host: host + ":" + port, Path: "/" + database}
	if engine == "postgresql" {
		u.RawQuery = "sslmode=disable"
	}
	return u.String()
}

func (a *API) databaseDetails(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	password := ""
	if database.PasswordCipher != "" {
		if plain, err := a.secrets.Decrypt(database.PasswordCipher); err == nil {
			password = string(plain)
		}
	}
	result := map[string]any{
		"id": database.ID, "name": database.Name, "engine": database.Engine, "version": database.Version,
		"host": database.Host, "port": database.Port, "username": database.Username, "password": password,
		"database": database.DatabaseName, "managedMode": database.ManagedMode,
	}
	if password != "" {
		result["url"] = connectionURL(database.Engine, database.Username, password, database.Host, strconv.Itoa(database.Port), database.DatabaseName)
	}
	if database.Status != "running" || (database.Engine != "postgresql" && database.Engine != "postgres") {
		result["tables"] = []any{}
		writeJSON(w, 200, result)
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
	namespace, target := "minipaas-data", "statefulset/db-"+kubeName(database.Name)+"-"+idSuffix(database.ID)
	if database.ManagedMode == "adopted" {
		namespace, target = database.Namespace, "deployment/"+database.Workload
	}
	table := strings.TrimSpace(r.URL.Query().Get("table"))
	if table != "" && !databaseTablePattern.MatchString(table) {
		writeJSON(w, 400, map[string]string{"error": "数据表名称格式不正确"})
		return
	}
	sql := `SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT relname AS name,n_live_tup AS rows FROM pg_stat_user_tables ORDER BY relname) t;`
	if table != "" {
		sql = fmt.Sprintf(`SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT * FROM "%s" LIMIT 100) t;`, table)
	}
	sqlEncoded := base64.StdEncoding.EncodeToString([]byte(sql))
	script := fmt.Sprintf(`set -eu
k3s kubectl -n %s exec %s -- sh -lc 'sql=$(printf %%s %s | base64 -d); psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$sql"'
`, namespace, target, sqlEncoded)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, runErr := client.run(ctx, script, 40*time.Second)
	if runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "读取数据库失败", "output": tailText(out, 1200)})
		return
	}
	var rows any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &rows) != nil {
		writeJSON(w, 502, map[string]string{"error": "数据库返回内容无法解析"})
		return
	}
	if table == "" {
		result["tables"] = rows
	} else {
		result["table"], result["rows"] = table, rows
	}
	writeJSON(w, 200, result)
}

func (a *API) databaseRename(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "显示名称不能为空"})
		return
	}
	err := a.store.mutate(func(s *State) error {
		for i := range s.Databases {
			if s.Databases[i].ID == r.PathValue("id") {
				s.Databases[i].Name = input.Name
				appendAudit(s, "database.rename", s.Databases[i].ID, "已修改数据库显示名称："+input.Name, nil)
				return nil
			}
		}
		return errors.New("数据库不存在")
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
