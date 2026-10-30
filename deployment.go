package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func kubeName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if valid {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		result = "app"
	}
	if len(result) > 38 {
		result = strings.TrimRight(result[:38], "-")
	}
	return result
}

func (a *API) findAppAndServer(appID string) (App, Server, error) {
	state := a.store.Snapshot()
	var app App
	found := false
	for _, item := range state.Apps {
		if item.ID == appID {
			app, found = item, true
			break
		}
	}
	if !found {
		return App{}, Server{}, errors.New("应用不存在")
	}
	for _, server := range state.Servers {
		if server.ID == app.ServerID {
			return app, server, nil
		}
	}
	return App{}, Server{}, errors.New("目标服务器不存在")
}

func (a *API) appDeploy(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	if app.ManagedMode == "adopted" {
		a.restartAdoptedApp(w, r, app, server, key)
		return
	}
	if app.Port < 1 || app.Port > 65535 {
		app.Port = 8080
	}
	pendingImage := ""
	if app.SourceType == "image" {
		pendingImage = app.Image
	}
	if err := a.setAppDeploymentState(app.ID, "deploying", "正在准备部署…", pendingImage); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Minute)
	defer cancel()
	if app.SourceType == "upload" {
		localPath := filepath.Join(a.dataDir, "uploads", app.ID, app.ArchiveName)
		if _, err := os.Stat(localPath); err != nil {
			a.deployFailed(app.ID, "找不到已上传的源码包")
			writeJSON(w, 400, map[string]string{"error": "找不到已上传的源码包，请重新创建应用并上传"})
			return
		}
		remotePath := "/var/lib/minipaas/uploads/" + app.ID + "/" + app.ArchiveName
		if err := client.Upload(ctx, localPath, remotePath); err != nil {
			message := "上传源码到目标服务器失败: " + err.Error()
			a.deployFailed(app.ID, message)
			writeJSON(w, 502, map[string]string{"error": message})
			return
		}
	}
	manifest, image, err := a.deploymentManifest(app)
	if err != nil {
		a.deployFailed(app.ID, err.Error())
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	buildEnv, err := a.frontendBuildEnv(app)
	if err != nil {
		a.deployFailed(app.ID, err.Error())
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	script := buildDeployScript(app, manifest, image, buildEnv)
	if app.SourceType == "image" {
		script = buildImageDeployScript(app, manifest)
	}
	output, runErr := client.run(ctx, script, 32*time.Minute)
	if runErr != nil {
		message := fmt.Sprintf("部署失败: %v\n%s", runErr, output)
		a.deployFailed(app.ID, message)
		writeJSON(w, 502, map[string]string{"error": "部署失败", "output": tailText(output, 12000)})
		return
	}
	gitCommit := app.GitCommit
	if app.SourceType == "git" {
		commitCtx, commitCancel := context.WithTimeout(r.Context(), time.Minute)
		if current, commitErr := a.currentGitCommit(commitCtx, app, server, key); commitErr == nil {
			gitCommit = current
		}
		commitCancel()
	}
	_ = a.store.mutate(func(state *State) error {
		for i := range state.Apps {
			if state.Apps[i].ID != app.ID {
				continue
			}
			if state.Apps[i].Image != "" && state.Apps[i].Image != image {
				state.Apps[i].Revisions = appendRevision(state.Apps[i].Revisions, DeploymentRevision{ID: newID("rev"), Image: state.Apps[i].Image, GitCommit: state.Apps[i].GitCommit, DeployedAt: state.Apps[i].DeployedAt, Reason: "历史部署"})
			}
			state.Apps[i].Status, state.Apps[i].Image, state.Apps[i].DeployLog = "running", image, tailText(output, 20000)
			state.Apps[i].DeployedAt, state.Apps[i].UpdatedAt = time.Now(), time.Now()
			state.Apps[i].GitCommit, state.Apps[i].GitCheckedAt, state.Apps[i].AutoDeployError = gitCommit, time.Now(), ""
			state.Apps[i].Revisions = appendRevision(state.Apps[i].Revisions, DeploymentRevision{ID: newID("rev"), Image: image, GitCommit: gitCommit, DeployedAt: state.Apps[i].DeployedAt, Reason: "部署成功"})
			for j := range state.Apps[i].Domains {
				state.Apps[i].Domains[j].Status = "active"
			}
		}
		appendAudit(state, "app.deploy", app.ID, "应用 "+app.Name+" 部署成功", map[string]any{"image": image})
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "image": image, "output": tailText(output, 12000)})
}

func appendRevision(items []DeploymentRevision, revision DeploymentRevision) []DeploymentRevision {
	if revision.DeployedAt.IsZero() {
		revision.DeployedAt = time.Now()
	}
	for _, item := range items {
		if item.Image == revision.Image && item.GitCommit == revision.GitCommit {
			return items
		}
	}
	items = append(items, revision)
	if len(items) > 12 {
		items = items[len(items)-12:]
	}
	return items
}

func (a *API) appHistory(w http.ResponseWriter, r *http.Request) {
	app, _, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	items := append([]DeploymentRevision(nil), app.Revisions...)
	if app.Image != "" {
		found := false
		for _, item := range items {
			if item.Image == app.Image {
				found = true
				break
			}
		}
		if !found {
			items = append(items, DeploymentRevision{ID: "current", Image: app.Image, GitCommit: app.GitCommit, DeployedAt: app.DeployedAt, Reason: "当前运行版本"})
		}
	}
	writeJSON(w, 200, map[string]any{"currentImage": app.Image, "managedMode": app.ManagedMode, "revisions": items})
}

func (a *API) appRollback(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if app.ManagedMode == "adopted" {
		writeJSON(w, 400, map[string]string{"error": "接管应用没有 MiniPaaS 构建版本，无法一键回滚"})
		return
	}
	var input struct {
		RevisionID string `json:"revisionId"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var target DeploymentRevision
	for _, item := range app.Revisions {
		if item.ID == input.RevisionID {
			target = item
			break
		}
	}
	if target.ID == "" || target.Image == "" {
		writeJSON(w, 404, map[string]string{"error": "部署版本不存在"})
		return
	}
	if target.Image == app.Image {
		writeJSON(w, 400, map[string]string{"error": "该版本已经在运行"})
		return
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
	script := fmt.Sprintf(`set -euo pipefail
image=$(printf '%%s' '%s' | base64 -d)
k3s kubectl -n minipaas-apps set image deployment/%s "app=$image"
k3s kubectl -n minipaas-apps rollout status deployment/%s --timeout=300s
k3s kubectl -n minipaas-apps get deployment/%s -o wide
`, shellB64(target.Image), name, name, name)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Minute)
	defer cancel()
	out, runErr := client.run(ctx, script, 6*time.Minute)
	if runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "回滚失败，原运行版本会继续提供服务", "output": tailText(out, 5000)})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Apps {
			if s.Apps[i].ID != app.ID {
				continue
			}
			s.Apps[i].Revisions = appendRevision(s.Apps[i].Revisions, DeploymentRevision{ID: newID("rev"), Image: app.Image, GitCommit: app.GitCommit, DeployedAt: app.DeployedAt, Reason: "回滚前版本"})
			s.Apps[i].Image, s.Apps[i].GitCommit, s.Apps[i].Status = target.Image, target.GitCommit, "running"
			s.Apps[i].DeployedAt, s.Apps[i].UpdatedAt, s.Apps[i].DeployLog = time.Now(), time.Now(), tailText(out, 12000)
		}
		appendAudit(s, "app.rollback", app.ID, "应用 "+app.Name+" 已回滚", map[string]any{"image": target.Image})
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "image": target.Image, "output": tailText(out, 5000)})
}

func (a *API) appRuntimeLogs(w http.ResponseWriter, r *http.Request) {
	app, server, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	namespace, workload := "minipaas-apps", "mp-"+kubeName(app.Name)+"-"+idSuffix(app.ID)
	if app.ManagedMode == "adopted" {
		if !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(app.Namespace) || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(app.Workload) {
			writeJSON(w, 400, map[string]string{"error": "接管资源标识不安全"})
			return
		}
		namespace, workload = app.Namespace, app.Workload
	}
	key, err := a.secrets.Decrypt(server.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	script := fmt.Sprintf(`k3s kubectl -n %s logs deployment/%s --tail=500 --timestamps=true 2>&1`, namespace, workload)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	out, runErr := client.run(ctx, script, 30*time.Second)
	if runErr != nil {
		writeJSON(w, 502, map[string]string{"error": "读取运行日志失败", "output": tailText(out, 3000)})
		return
	}
	writeJSON(w, 200, map[string]any{"logs": tailText(out, 40000), "updatedAt": time.Now()})
}

func (a *API) frontendBuildEnv(app App) (string, error) {
	lines := []string{}
	for _, variable := range app.Variables {
		if !strings.HasPrefix(variable.Key, "VITE_") && !strings.HasPrefix(variable.Key, "NEXT_PUBLIC_") && !strings.HasPrefix(variable.Key, "PUBLIC_") {
			continue
		}
		value := variable.Value
		if variable.EncryptedValue != "" {
			plain, err := a.secrets.Decrypt(variable.EncryptedValue)
			if err != nil {
				return "", fmt.Errorf("无法解密前端构建变量 %s", variable.Key)
			}
			value = string(plain)
		}
		value = strings.ReplaceAll(value, "\\", "\\\\")
		value = strings.ReplaceAll(value, "\n", "\\n")
		value = strings.ReplaceAll(value, "\"", "\\\"")
		lines = append(lines, variable.Key+"=\""+value+"\"")
	}
	return strings.Join(lines, "\n"), nil
}

func (a *API) restartAdoptedApp(w http.ResponseWriter, r *http.Request, app App, server Server, key []byte) {
	if !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(app.Namespace) || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(app.Workload) {
		writeJSON(w, 400, map[string]string{"error": "已接管资源标识不安全"})
		return
	}
	script := fmt.Sprintf(`set -e
k3s kubectl -n %s rollout restart deployment/%s
k3s kubectl -n %s rollout status deployment/%s --timeout=240s
k3s kubectl -n %s get deployment,pod,service -l app=app -o wide
`, app.Namespace, app.Workload, app.Namespace, app.Workload, app.Namespace)
	client := RemoteClient{Server: server, PrivateKey: key}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	output, runErr := client.run(ctx, script, 4*time.Minute)
	if runErr != nil {
		_ = a.setAppDeploymentState(app.ID, "failed", tailText(output, 12000), app.Image)
		writeJSON(w, 502, map[string]string{"error": "重启已接管应用失败", "output": tailText(output, 6000)})
		return
	}
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Apps {
			if s.Apps[i].ID == app.ID {
				s.Apps[i].Status, s.Apps[i].DeployLog, s.Apps[i].UpdatedAt = "running", tailText(output, 12000), time.Now()
			}
		}
		appendAudit(s, "app.restart", app.ID, "已重启接管应用 "+app.Name, nil)
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "output": tailText(output, 6000)})
}

func (a *API) appConfig(w http.ResponseWriter, r *http.Request) {
	app, _, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var input struct {
		Port               int        `json:"port"`
		Domain             string     `json:"domain"`
		SourceType         string     `json:"sourceType"`
		Repository         string     `json:"repository"`
		Branch             string     `json:"branch"`
		BuildType          string     `json:"buildType"`
		VariablesFromAppID string     `json:"variablesFromAppId"`
		AutoDeploy         *bool      `json:"autoDeploy"`
		Variables          []Variable `json:"variables"`
		DatabaseID         string     `json:"databaseId"`
		PreserveDomains    bool       `json:"preserveDomains"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if input.Port < 1 || input.Port > 65535 {
		writeJSON(w, 400, map[string]string{"error": "应用端口必须在 1-65535 之间"})
		return
	}
	if input.SourceType == "" {
		input.SourceType = app.SourceType
	}
	if input.SourceType != "git" && input.SourceType != "upload" && input.SourceType != "image" {
		writeJSON(w, 400, map[string]string{"error": "源码类型不正确"})
		return
	}
	input.Repository = strings.TrimSpace(input.Repository)
	input.Branch = strings.TrimSpace(input.Branch)
	input.BuildType = strings.TrimSpace(input.BuildType)
	if input.SourceType == "git" && input.Repository == "" {
		writeJSON(w, 400, map[string]string{"error": "Git 应用必须填写仓库地址"})
		return
	}
	if input.Branch == "" {
		input.Branch = "main"
	}
	if input.BuildType == "" {
		input.BuildType = "auto"
	}
	domain := strings.ToLower(strings.TrimSpace(input.Domain))
	if domain != "" && !domainPattern.MatchString(domain) {
		writeJSON(w, 400, map[string]string{"error": "域名格式不正确"})
		return
	}
	oldSecrets := map[string]string{}
	for _, variable := range app.Variables {
		if variable.EncryptedValue != "" {
			oldSecrets[variable.Key] = variable.EncryptedValue
		}
	}
	variables := []Variable{}
	for _, variable := range input.Variables {
		variable.Key = strings.TrimSpace(variable.Key)
		if variable.Key == "" {
			continue
		}
		if !envKeyPattern.MatchString(variable.Key) {
			writeJSON(w, 400, map[string]string{"error": "环境变量名称不正确: " + variable.Key})
			return
		}
		if variable.Value == "••••••••" {
			if saved := oldSecrets[variable.Key]; saved != "" {
				variable.EncryptedValue, variable.Value, variable.Secret = saved, "", true
				variables = append(variables, variable)
				continue
			}
		}
		ciphertext, encryptErr := a.secrets.Encrypt([]byte(variable.Value))
		if encryptErr != nil {
			writeJSON(w, 500, map[string]string{"error": "无法加密环境变量"})
			return
		}
		variable.EncryptedValue, variable.Value, variable.Secret = ciphertext, "", true
		variables = append(variables, variable)
	}
	if input.VariablesFromAppID != "" {
		found := false
		for _, source := range a.store.Snapshot().Apps {
			if source.ID == input.VariablesFromAppID && source.ServerID == app.ServerID {
				variables = append([]Variable(nil), source.Variables...)
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, 400, map[string]string{"error": "变量来源应用不存在或不在同一服务器"})
			return
		}
	}
	if input.DatabaseID != "" {
		state := a.store.Snapshot()
		var database Database
		dbFound := false
		for _, item := range state.Databases {
			if item.ID == input.DatabaseID && item.ServerID == app.ServerID {
				database, dbFound = item, true
				break
			}
		}
		if !dbFound || database.Status != "running" {
			writeJSON(w, 400, map[string]string{"error": "所选数据库尚未部署或不在同一服务器"})
			return
		}
		password, decryptErr := a.secrets.Decrypt(database.PasswordCipher)
		if decryptErr != nil {
			writeJSON(w, 500, map[string]string{"error": "无法读取数据库密码"})
			return
		}
		value := connectionURL(database.Engine, database.Username, string(password), database.Host, strconv.Itoa(database.Port), database.DatabaseName)
		ciphertext, encryptErr := a.secrets.Encrypt([]byte(value))
		if encryptErr != nil {
			writeJSON(w, 500, map[string]string{"error": "无法生成数据库变量"})
			return
		}
		replaced := false
		for i := range variables {
			if variables[i].Key == "DATABASE_URL" {
				variables[i].EncryptedValue, variables[i].Value, variables[i].Secret, replaced = ciphertext, "", true, true
			}
		}
		if !replaced {
			variables = append(variables, Variable{Key: "DATABASE_URL", EncryptedValue: ciphertext, Secret: true})
		}
	}
	err = a.store.mutate(func(state *State) error {
		for i := range state.Apps {
			if state.Apps[i].ID != app.ID {
				continue
			}
			state.Apps[i].Port, state.Apps[i].Variables, state.Apps[i].DatabaseID, state.Apps[i].UpdatedAt = input.Port, variables, input.DatabaseID, time.Now()
			state.Apps[i].SourceType, state.Apps[i].Repository, state.Apps[i].Branch, state.Apps[i].BuildType = input.SourceType, input.Repository, input.Branch, input.BuildType
			if input.AutoDeploy != nil {
				state.Apps[i].AutoDeploy = *input.AutoDeploy
			}
			if !input.PreserveDomains {
				if domain == "" {
					state.Apps[i].Domains = nil
				} else {
					state.Apps[i].Domains = []Domain{{Host: domain, HTTPS: true, Status: "pending", TargetPort: input.Port}}
				}
			}
		}
		appendAudit(state, "app.config", app.ID, "已更新应用 "+app.Name+" 的配置", nil)
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) deployFailed(appID, message string) {
	_ = a.store.mutate(func(state *State) error {
		for i := range state.Apps {
			if state.Apps[i].ID == appID {
				state.Apps[i].Status, state.Apps[i].DeployLog, state.Apps[i].UpdatedAt = "failed", tailText(message, 20000), time.Now()
			}
		}
		appendAudit(state, "app.deploy.failed", appID, "应用部署失败", nil)
		return nil
	})
}

func (a *API) setAppDeploymentState(appID, status, logText, image string) error {
	return a.store.mutate(func(state *State) error {
		for i := range state.Apps {
			if state.Apps[i].ID == appID {
				state.Apps[i].Status, state.Apps[i].DeployLog, state.Apps[i].Image, state.Apps[i].UpdatedAt = status, logText, image, time.Now()
			}
		}
		return nil
	})
}

func tailText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:]
}

func (a *API) appVariables(w http.ResponseWriter, r *http.Request) {
	app, _, err := a.findAppAndServer(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	result := make([]Variable, 0, len(app.Variables))
	for _, variable := range app.Variables {
		value := variable.Value
		if variable.EncryptedValue != "" {
			plain, decryptErr := a.secrets.Decrypt(variable.EncryptedValue)
			if decryptErr != nil {
				writeJSON(w, 500, map[string]string{"error": "无法解密环境变量 " + variable.Key})
				return
			}
			value = string(plain)
		}
		result = append(result, Variable{Key: variable.Key, Value: value, Secret: variable.Secret, Required: variable.Required})
	}
	writeJSON(w, 200, result)
}

func (a *API) deploymentManifest(app App) ([]byte, string, error) {
	name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
	image := app.Image
	if image == "" || app.SourceType != "image" {
		image = "localhost/minipaas/" + name + ":" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	stringData := map[string]string{}
	for _, variable := range app.Variables {
		if !envKeyPattern.MatchString(variable.Key) {
			return nil, "", fmt.Errorf("环境变量名称不正确: %s", variable.Key)
		}
		value := variable.Value
		if variable.EncryptedValue != "" {
			plain, err := a.secrets.Decrypt(variable.EncryptedValue)
			if err != nil {
				return nil, "", fmt.Errorf("无法解密环境变量 %s", variable.Key)
			}
			value = string(plain)
		}
		stringData[variable.Key] = value
	}
	labels := map[string]any{"app.kubernetes.io/name": name, "app.kubernetes.io/managed-by": "minipaas"}
	secret := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name + "-env", "namespace": "minipaas-apps"}, "type": "Opaque", "stringData": stringData}
	pullPolicy := "Never"
	if app.SourceType == "image" {
		pullPolicy = "IfNotPresent"
	}
	container := map[string]any{"name": "app", "image": image, "imagePullPolicy": pullPolicy, "ports": []any{map[string]any{"name": "http", "containerPort": app.Port}}, "envFrom": []any{map[string]any{"secretRef": map[string]any{"name": name + "-env"}}}, "resources": map[string]any{"requests": map[string]any{"cpu": "25m", "memory": "64Mi"}, "limits": map[string]any{"memory": "768Mi"}}, "readinessProbe": map[string]any{"tcpSocket": map[string]any{"port": "http"}, "initialDelaySeconds": 3, "periodSeconds": 5}, "livenessProbe": map[string]any{"tcpSocket": map[string]any{"port": "http"}, "initialDelaySeconds": 15, "periodSeconds": 15}}
	deployment := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": name, "namespace": "minipaas-apps", "labels": labels}, "spec": map[string]any{"replicas": 1, "revisionHistoryLimit": 3, "selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{container}}}}}
	service := map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": name, "namespace": "minipaas-apps", "labels": labels}, "spec": map[string]any{"selector": labels, "ports": []any{map[string]any{"name": "http", "port": app.Port, "targetPort": "http"}}}}
	manifest := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{secret, deployment, service}}
	b, err := json.Marshal(manifest)
	return b, image, err
}

func buildImageDeployScript(app App, manifest []byte) string {
	name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
	return fmt.Sprintf(`set -euo pipefail
printf '%%s' '%s' | base64 -d | k3s kubectl apply -f -
k3s kubectl -n minipaas-apps rollout status deployment/%s --timeout=240s
echo 'MINIPAAS_IMAGE_DEPLOY_OK'
k3s kubectl -n minipaas-apps get deployment,service -l app.kubernetes.io/name=%s -o wide
`, base64.StdEncoding.EncodeToString(manifest), name, name)
}

func shellB64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func buildDeployScript(app App, manifest []byte, image, buildEnv string) string {
	name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
	domain := ""
	if len(app.Domains) > 0 {
		domain = strings.ToLower(strings.TrimSpace(app.Domains[0].Host))
		if !domainPattern.MatchString(domain) {
			domain = ""
		}
	}
	return fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
base='/var/lib/minipaas/builds/%s'
source_dir="$base/source"
mkdir -p "$base" /var/lib/minipaas/uploads/%s
if ! command -v buildah >/dev/null 2>&1; then apt-get update; apt-get install -y buildah unzip; fi
mkdir -p /etc/containers; touch /etc/containers/registries.conf
sed -i '/^unqualified-search-registries[[:space:]]*=/d' /etc/containers/registries.conf
printf '%%s\n' 'unqualified-search-registries = ["docker.io"]' >> /etc/containers/registries.conf
source_type=$(printf '%%s' '%s' | base64 -d)
if [ "$source_type" = git ]; then
  repo=$(printf '%%s' '%s' | base64 -d)
  branch=$(printf '%%s' '%s' | base64 -d)
  if [ -d "$source_dir/.git" ]; then git -C "$source_dir" fetch --prune origin; git -C "$source_dir" checkout -B "$branch" "origin/$branch"; else rm -rf "$source_dir"; git clone --depth 1 --branch "$branch" "$repo" "$source_dir"; fi
else
  archive="/var/lib/minipaas/uploads/%s/%s"
  rm -rf "$source_dir"; mkdir -p "$source_dir"
  case "$archive" in *.zip) unzip -q "$archive" -d "$source_dir";; *.tar.gz|*.tgz) tar -xzf "$archive" -C "$source_dir";; *) echo 'Unsupported archive'; exit 21;; esac
  first=$(find "$source_dir" -mindepth 1 -maxdepth 1 | head -1 || true)
  count=$(find "$source_dir" -mindepth 1 -maxdepth 1 | wc -l)
  if [ "$count" -eq 1 ] && [ -d "$first" ]; then cp -a "$first"/. "$source_dir/.flatten"; rm -rf "$first"; cp -a "$source_dir/.flatten"/. "$source_dir"/; rm -rf "$source_dir/.flatten"; fi
fi
cd "$source_dir"
if [ "$source_type" = git ] && ! git ls-files --error-unmatch Dockerfile >/dev/null 2>&1; then
  rm -f Dockerfile
fi
printf '%%s' '%s' | base64 -d > .env.production.local
chmod 600 .env.production.local
build_type=$(printf '%%s' '%s' | base64 -d)
port='%d'
if [ ! -f Dockerfile ]; then
  if [ -f pnpm-workspace.yaml ] && [ -f artifacts/api-server/package.json ] && { [ "$build_type" = auto ] || [ "$build_type" = node ]; }; then
    cat >Dockerfile <<'DOCKERFILE'
FROM docker.io/library/node:24-alpine AS build
WORKDIR /work
RUN npm install -g pnpm@10
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @workspace/api-server run build
FROM docker.io/library/node:24-alpine
WORKDIR /work
COPY --from=build /work/artifacts/api-server/dist /work/artifacts/api-server/dist
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node", "--enable-source-maps", "/work/artifacts/api-server/dist/index.mjs"]
DOCKERFILE
  elif [ -f package.json ] && { [ "$build_type" = auto ] || [ "$build_type" = node ]; }; then
    if grep -Eq '"start"[[:space:]]*:' package.json; then
      cat >Dockerfile <<DOCKERFILE
FROM docker.io/library/node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
RUN npm run build --if-present && npm prune --omit=dev
ENV NODE_ENV=production PORT=$port
EXPOSE $port
CMD ["npm", "start"]
DOCKERFILE
    else
      port=80
      cat >Dockerfile <<'DOCKERFILE'
FROM docker.io/library/node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
RUN npm run build
FROM docker.io/library/nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
RUN printf 'server { listen 80; server_name _; root /usr/share/nginx/html; index index.html; location / { try_files $uri $uri/ /index.html; } }\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
DOCKERFILE
    fi
  elif [ "$build_type" = static ] || { [ "$build_type" = auto ] && [ -f index.html ]; }; then
    cat >Dockerfile <<'DOCKERFILE'
FROM docker.io/library/nginx:1.27-alpine
COPY . /usr/share/nginx/html
DOCKERFILE
  else echo 'No Dockerfile and project type was not recognized'; exit 22; fi
fi
image='%s'
archive_image="$base/image.tar"
buildah bud --isolation chroot -t "$image" .
rm -f .env.production.local
rm -f "$archive_image"
buildah push "$image" "docker-archive:$archive_image:$image"
k3s ctr images import "$archive_image"
printf '%%s' '%s' | base64 -d | k3s kubectl apply -f -
k3s kubectl -n minipaas-apps rollout status deployment/%s --timeout=240s
domain=$(printf '%%s' '%s' | base64 -d)
if [ -n "$domain" ] && k3s kubectl -n default get configmap independent-caddy-config >/dev/null 2>&1; then
  k3s kubectl -n default get configmap independent-caddy-config -o jsonpath='{.data.Caddyfile}' > "$base/Caddyfile"
  if ! grep -Fq "$domain" "$base/Caddyfile"; then
    cat >>"$base/Caddyfile" <<CADDY

http://$domain, https://$domain {
  encode zstd gzip
  reverse_proxy %s.minipaas-apps.svc.cluster.local:%d
}
CADDY
    k3s kubectl -n default create configmap independent-caddy-config --from-file=Caddyfile="$base/Caddyfile" --dry-run=client -o yaml | k3s kubectl apply -f -
    k3s kubectl -n default rollout restart daemonset independent-caddy
    k3s kubectl -n default rollout status daemonset independent-caddy --timeout=120s
  fi
fi
echo 'MINIPAAS_DEPLOY_OK'
k3s kubectl -n minipaas-apps get deployment,service -l app.kubernetes.io/name=%s -o wide
`, app.ID, app.ID, shellB64(app.SourceType), shellB64(app.Repository), shellB64(app.Branch), app.ID, app.ArchiveName, shellB64(buildEnv), shellB64(app.BuildType), app.Port, image, base64.StdEncoding.EncodeToString(manifest), name, shellB64(domain), name, app.Port, name)
}
