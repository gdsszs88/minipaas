package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	User               string    `json:"user"`
	Status             string    `json:"status"`
	K3sVersion         string    `json:"k3sVersion,omitempty"`
	CPU                int       `json:"cpu,omitempty"`
	MemoryMB           int       `json:"memoryMB,omitempty"`
	DiskGB             int       `json:"diskGB,omitempty"`
	LastSeenAt         time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt          time.Time `json:"createdAt"`
	Description        string    `json:"description,omitempty"`
	AuthType           string    `json:"authType,omitempty"`
	Credential         string    `json:"credential,omitempty"`
	HostKeyFingerprint string    `json:"hostKeyFingerprint,omitempty"`
}

type Variable struct {
	Key            string `json:"key"`
	Value          string `json:"value,omitempty"`
	EncryptedValue string `json:"encryptedValue,omitempty"`
	Secret         bool   `json:"secret"`
	Required       bool   `json:"required,omitempty"`
}

type Domain struct {
	Host       string `json:"host"`
	HTTPS      bool   `json:"https"`
	Status     string `json:"status"`
	TargetPort int    `json:"targetPort"`
}

type App struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	ServerID        string     `json:"serverId"`
	SourceType      string     `json:"sourceType"`
	Repository      string     `json:"repository,omitempty"`
	Branch          string     `json:"branch,omitempty"`
	BuildType       string     `json:"buildType"`
	Status          string     `json:"status"`
	Image           string     `json:"image,omitempty"`
	ArchiveName     string     `json:"archiveName,omitempty"`
	UploadPath      string     `json:"-"`
	Port            int        `json:"port,omitempty"`
	DeployLog       string     `json:"deployLog,omitempty"`
	DeployedAt      time.Time  `json:"deployedAt,omitempty"`
	DatabaseID      string     `json:"databaseId,omitempty"`
	Variables       []Variable `json:"variables,omitempty"`
	Domains         []Domain   `json:"domains,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	ManagedMode     string     `json:"managedMode,omitempty"`
	Namespace       string     `json:"namespace,omitempty"`
	Workload        string     `json:"workload,omitempty"`
	ServiceName     string     `json:"serviceName,omitempty"`
	AutoDeploy      bool       `json:"autoDeploy,omitempty"`
	GitCommit       string     `json:"gitCommit,omitempty"`
	GitCheckedAt    time.Time  `json:"gitCheckedAt,omitempty"`
	AutoDeployError string     `json:"autoDeployError,omitempty"`
}

type Database struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Engine         string    `json:"engine"`
	Version        string    `json:"version"`
	ServerID       string    `json:"serverId"`
	Status         string    `json:"status"`
	StorageGB      int       `json:"storageGB"`
	Username       string    `json:"username,omitempty"`
	DatabaseName   string    `json:"databaseName,omitempty"`
	Host           string    `json:"host,omitempty"`
	Port           int       `json:"port,omitempty"`
	PasswordCipher string    `json:"passwordCipher,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	ManagedMode    string    `json:"managedMode,omitempty"`
	Namespace      string    `json:"namespace,omitempty"`
	Workload       string    `json:"workload,omitempty"`
	ServiceName    string    `json:"serviceName,omitempty"`
	PVCName        string    `json:"pvcName,omitempty"`
}

type AuditEvent struct {
	ID        string         `json:"id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
}

type State struct {
	Servers   []Server     `json:"servers"`
	Apps      []App        `json:"apps"`
	Databases []Database   `json:"databases"`
	Audit     []AuditEvent `json:"audit"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data State
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: State{Servers: []Server{}, Apps: []App{}, Databases: []Database{}, Audit: []AuditEvent{}}}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("decode state: %w", err)
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.data)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Store) mutate(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.data); err != nil {
		return err
	}
	return s.saveLocked()
}

type session struct{ Expires time.Time }

type API struct {
	store      *Store
	password   [32]byte
	passwordMu sync.RWMutex
	sessions   map[string]session
	sessionMu  sync.Mutex
	sessionTTL time.Duration
	secrets    *SecretBox
	dataDir    string
	setupJobs  map[string]*SetupJob
	setupMu    sync.RWMutex
}

func (a *API) passwordMatches(value string) bool {
	given := sha256.Sum256([]byte(value))
	a.passwordMu.RLock()
	defer a.passwordMu.RUnlock()
	return subtle.ConstantTimeCompare(given[:], a.password[:]) == 1
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !a.passwordMatches(input.Password) {
		time.Sleep(300 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "密码不正确"})
		return
	}
	token := newID("sess") + newID("")
	a.sessionMu.Lock()
	a.sessions[token] = session{Expires: time.Now().Add(a.sessionTTL)}
	a.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "minipaas_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expiresAt": time.Now().Add(a.sessionTTL)})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if !a.passwordMatches(input.CurrentPassword) {
		writeJSON(w, 403, map[string]string{"error": "当前密码不正确"})
		return
	}
	if input.NewPassword == "" {
		writeJSON(w, 400, map[string]string{"error": "新密码不能为空"})
		return
	}
	if input.CurrentPassword == input.NewPassword {
		writeJSON(w, 400, map[string]string{"error": "新密码不能与当前密码相同"})
		return
	}
	hash := sha256.Sum256([]byte(input.NewPassword))
	if err := os.WriteFile(filepath.Join(a.dataDir, "admin-password.sha256"), []byte(hex.EncodeToString(hash[:])+"\n"), 0600); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存新密码失败"})
		return
	}
	a.passwordMu.Lock()
	a.password = hash
	a.passwordMu.Unlock()
	currentToken := ""
	if c, err := r.Cookie("minipaas_session"); err == nil {
		currentToken = c.Value
	}
	a.sessionMu.Lock()
	for token := range a.sessions {
		if token != currentToken {
			delete(a.sessions, token)
		}
	}
	a.sessionMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("minipaas_session"); err == nil {
		a.sessionMu.Lock()
		delete(a.sessions, c.Value)
		a.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "minipaas_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("minipaas_session")
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		a.sessionMu.Lock()
		s, ok := a.sessions[c.Value]
		if ok && time.Now().After(s.Expires) {
			delete(a.sessions, c.Value)
			ok = false
		}
		a.sessionMu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) dashboard(w http.ResponseWriter, _ *http.Request) {
	s := a.store.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers": len(s.Servers), "onlineServers": countServers(s.Servers, "online"),
		"apps": len(s.Apps), "runningApps": countApps(s.Apps, "running"),
		"databases": len(s.Databases), "audit": lastAudit(s.Audit, 8),
	})
}

func countServers(items []Server, status string) int {
	n := 0
	for _, v := range items {
		if v.Status == status {
			n++
		}
	}
	return n
}
func countApps(items []App, status string) int {
	n := 0
	for _, v := range items {
		if v.Status == status {
			n++
		}
	}
	return n
}
func lastAudit(items []AuditEvent, n int) []AuditEvent {
	if len(items) <= n {
		return items
	}
	return items[len(items)-n:]
}

func (a *API) servers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := a.store.Snapshot().Servers
		for i := range items {
			items[i].Credential = ""
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var request struct {
			Server
			PrivateKey string `json:"privateKey"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		input := request.Server
		input.Name = strings.TrimSpace(input.Name)
		input.Host = strings.TrimSpace(input.Host)
		input.User = strings.TrimSpace(input.User)
		if input.Name == "" || input.Host == "" {
			writeJSON(w, 400, map[string]string{"error": "名称和主机不能为空"})
			return
		}
		if input.Port == 0 {
			input.Port = 22
		}
		if input.User == "" {
			input.User = "root"
		}
		if err := validateSSHAddress(input.Host, input.Port, input.User); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(request.PrivateKey) == "" {
			writeJSON(w, 400, map[string]string{"error": "必须提供 SSH 私钥"})
			return
		}
		ciphertext, err := a.secrets.Encrypt([]byte(request.PrivateKey))
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "无法加密私钥"})
			return
		}
		input.AuthType, input.Credential = "privateKey", ciphertext
		input.ID, input.Status, input.CreatedAt = newID("srv"), "pending", time.Now()
		err = a.store.mutate(func(s *State) error {
			s.Servers = append(s.Servers, input)
			appendAudit(s, "server.create", input.ID, "已添加服务器 "+input.Name, nil)
			return nil
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		input.Credential = ""
		writeJSON(w, http.StatusCreated, input)
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func (a *API) serverAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	var target Server
	found := false
	for _, item := range a.store.Snapshot().Servers {
		if item.ID == id {
			target, found = item, true
			break
		}
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "服务器不存在"})
		return
	}
	key, err := a.secrets.Decrypt(target.Credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法读取服务器凭据"})
		return
	}
	client := RemoteClient{Server: target, PrivateKey: key}
	switch action {
	case "test":
		info, err := client.Probe(r.Context())
		if err != nil {
			a.updateServerProbe(id, "offline", RemoteInfo{})
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		a.updateServerProbe(id, "online", info)
		writeJSON(w, 200, info)
	case "bootstrap":
		result, err := client.BootstrapK3s(r.Context())
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error(), "output": result})
			return
		}
		info, _ := client.Probe(r.Context())
		a.updateServerProbe(id, "online", info)
		_ = a.store.mutate(func(s *State) error {
			appendAudit(s, "server.bootstrap", id, "K3s 引导安装完成", nil)
			return nil
		})
		writeJSON(w, 200, map[string]any{"ok": true, "output": result, "info": info})
	default:
		writeJSON(w, 404, map[string]string{"error": "未知操作"})
	}
}

func (a *API) updateServerProbe(id, status string, info RemoteInfo) {
	_ = a.store.mutate(func(s *State) error {
		for i := range s.Servers {
			if s.Servers[i].ID != id {
				continue
			}
			s.Servers[i].Status = status
			s.Servers[i].LastSeenAt = time.Now()
			if info.K3sVersion != "" {
				s.Servers[i].K3sVersion = info.K3sVersion
			}
			if info.CPU > 0 {
				s.Servers[i].CPU = info.CPU
			}
			if info.MemoryMB > 0 {
				s.Servers[i].MemoryMB = info.MemoryMB
			}
			if info.DiskGB > 0 {
				s.Servers[i].DiskGB = info.DiskGB
			}
			if info.HostKeyFingerprint != "" {
				s.Servers[i].HostKeyFingerprint = info.HostKeyFingerprint
			}
		}
		appendAudit(s, "server.probe", id, "服务器连接检测："+status, nil)
		return nil
	})
}

func (a *API) apps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := a.store.Snapshot().Apps
		for i := range items {
			items[i] = redactApp(items[i])
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var input App
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		input.Name = strings.TrimSpace(input.Name)
		if input.Name == "" || input.ServerID == "" {
			writeJSON(w, 400, map[string]string{"error": "应用名称和服务器不能为空"})
			return
		}
		if input.SourceType == "" {
			input.SourceType = "git"
		}
		input.AutoDeploy = true
		if input.Branch == "" {
			input.Branch = "main"
		}
		if input.BuildType == "" {
			input.BuildType = "auto"
		}
		if input.Port == 0 {
			input.Port = 8080
		}
		if err := a.encryptVariables(&input); err != nil {
			writeJSON(w, 500, map[string]string{"error": "无法加密环境变量"})
			return
		}
		now := time.Now()
		input.ID, input.Status, input.CreatedAt, input.UpdatedAt = newID("app"), "draft", now, now
		err := a.store.mutate(func(s *State) error {
			s.Apps = append(s.Apps, input)
			appendAudit(s, "app.create", input.ID, "已创建应用 "+input.Name, nil)
			return nil
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 201, redactApp(input))
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func safeArchiveName(name string) (string, bool) {
	name = filepath.Base(strings.TrimSpace(name))
	lower := strings.ToLower(name)
	valid := strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
	return name, valid && name != "." && name != ""
}

func copyMultipartFile(dst string, src multipart.File) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func (a *API) appUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeJSON(w, 400, map[string]string{"error": "无法读取上传内容，文件最大 512 MB"})
		return
	}
	name, serverID, buildType := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("serverId")), strings.TrimSpace(r.FormValue("buildType"))
	if name == "" || serverID == "" {
		writeJSON(w, 400, map[string]string{"error": "应用名称和服务器不能为空"})
		return
	}
	serverExists := false
	for _, server := range a.store.Snapshot().Servers {
		if server.ID == serverID {
			serverExists = true
			break
		}
	}
	if !serverExists {
		writeJSON(w, 400, map[string]string{"error": "目标服务器不存在"})
		return
	}
	file, header, err := r.FormFile("archive")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "请选择源码压缩包"})
		return
	}
	defer file.Close()
	archiveName, ok := safeArchiveName(header.Filename)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "只支持 .zip、.tar.gz 或 .tgz 源码包"})
		return
	}
	if buildType == "" {
		buildType = "auto"
	}
	now, id := time.Now(), newID("app")
	uploadPath := filepath.Join(a.dataDir, "uploads", id, archiveName)
	if err := copyMultipartFile(uploadPath, file); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存源码包失败"})
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 8080
	}
	app := App{ID: id, Name: name, ServerID: serverID, SourceType: "upload", BuildType: buildType, Status: "uploaded", ArchiveName: archiveName, UploadPath: uploadPath, Port: port, AutoDeploy: true, CreatedAt: now, UpdatedAt: now}
	if host := strings.TrimSpace(r.FormValue("domain")); host != "" {
		app.Domains = []Domain{{Host: host, HTTPS: true, Status: "pending", TargetPort: port}}
	}
	app.Variables = parseEnvText(r.FormValue("envText"))
	if err := a.encryptVariables(&app); err != nil {
		_ = os.RemoveAll(filepath.Dir(uploadPath))
		writeJSON(w, 500, map[string]string{"error": "无法加密环境变量"})
		return
	}
	if err := a.store.mutate(func(s *State) error {
		s.Apps = append(s.Apps, app)
		appendAudit(s, "app.upload", app.ID, "已上传本地源码 "+archiveName, map[string]any{"size": header.Size})
		return nil
	}); err != nil {
		_ = os.RemoveAll(filepath.Dir(uploadPath))
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, app)
}

func redactApp(app App) App {
	// App contains slice fields. A struct copy alone still shares their backing
	// arrays with the state store, so redacting the response could overwrite
	// the encrypted values kept in memory. Clone before masking anything.
	app.Variables = append([]Variable(nil), app.Variables...)
	app.Domains = append([]Domain(nil), app.Domains...)
	for i := range app.Variables {
		if app.Variables[i].Secret {
			app.Variables[i].Value = "••••••••"
		}
		app.Variables[i].EncryptedValue = ""
	}
	if len(app.DeployLog) > 4000 {
		app.DeployLog = app.DeployLog[len(app.DeployLog)-4000:]
	}
	return app
}

func parseEnvText(input string) []Variable {
	items := []Variable{}
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		items = append(items, Variable{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value), Secret: true})
	}
	return items
}

func (a *API) encryptVariables(app *App) error {
	for i := range app.Variables {
		app.Variables[i].Key = strings.TrimSpace(app.Variables[i].Key)
		if app.Variables[i].Key == "" {
			continue
		}
		ciphertext, err := a.secrets.Encrypt([]byte(app.Variables[i].Value))
		if err != nil {
			return err
		}
		app.Variables[i].EncryptedValue, app.Variables[i].Value, app.Variables[i].Secret = ciphertext, "", true
	}
	return nil
}

func (a *API) databases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := a.store.Snapshot().Databases
		for i := range items {
			items[i].PasswordCipher = ""
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var input Database
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if input.Name == "" || input.ServerID == "" {
			writeJSON(w, 400, map[string]string{"error": "数据库名称和服务器不能为空"})
			return
		}
		if input.Engine == "" {
			input.Engine = "postgresql"
		}
		if input.Version == "" {
			input.Version = "16"
		}
		if input.StorageGB == 0 {
			input.StorageGB = 10
		}
		input.ID, input.Status, input.CreatedAt = newID("db"), "pending", time.Now()
		err := a.store.mutate(func(s *State) error {
			s.Databases = append(s.Databases, input)
			appendAudit(s, "database.create", input.ID, "已创建数据库任务 "+input.Name, nil)
			return nil
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 201, input)
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func appendAudit(s *State, action, resource, message string, meta map[string]any) {
	s.Audit = append(s.Audit, AuditEvent{ID: newID("evt"), Action: action, Resource: resource, Message: message, Metadata: meta, CreatedAt: time.Now()})
	if len(s.Audit) > 1000 {
		s.Audit = s.Audit[len(s.Audit)-1000:]
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func main() {
	password := os.Getenv("MINIPAAS_ADMIN_PASSWORD")
	if passwordFile := strings.TrimSpace(os.Getenv("MINIPAAS_ADMIN_PASSWORD_FILE")); password == "" && passwordFile != "" {
		if value, readErr := os.ReadFile(passwordFile); readErr == nil {
			password = strings.TrimSpace(string(value))
		}
	}
	if password == "" {
		log.Fatal("必须设置 MINIPAAS_ADMIN_PASSWORD 或 MINIPAAS_ADMIN_PASSWORD_FILE")
	}
	dataDir := os.Getenv("MINIPAAS_DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	store, err := OpenStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		log.Fatal(err)
	}
	secretBox, err := OpenSecretBox(filepath.Join(dataDir, "master.key"))
	if err != nil {
		log.Fatal(err)
	}
	passwordHash := sha256.Sum256([]byte(password))
	if saved, readErr := os.ReadFile(filepath.Join(dataDir, "admin-password.sha256")); readErr == nil {
		if decoded, decodeErr := hex.DecodeString(strings.TrimSpace(string(saved))); decodeErr == nil && len(decoded) == sha256.Size {
			copy(passwordHash[:], decoded)
		}
	}
	api := &API{store: store, password: passwordHash, sessions: map[string]session{}, sessionTTL: envDuration("MINIPAAS_SESSION_TTL", 24*time.Hour), secrets: secretBox, dataDir: dataDir, setupJobs: map[string]*SetupJob{}}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", api.login)
	mux.Handle("POST /api/logout", api.auth(http.HandlerFunc(api.logout)))
	mux.Handle("POST /api/account/password", api.auth(http.HandlerFunc(api.changePassword)))
	mux.Handle("GET /api/dashboard", api.auth(http.HandlerFunc(api.dashboard)))
	mux.Handle("/api/servers", api.auth(http.HandlerFunc(api.servers)))
	mux.Handle("POST /api/servers/{id}/{action}", api.auth(http.HandlerFunc(api.serverAction)))
	mux.Handle("GET /api/servers/{id}/environment", api.auth(http.HandlerFunc(api.serverEnvironment)))
	mux.Handle("POST /api/servers/{id}/environment-install", api.auth(http.HandlerFunc(api.serverEnvironmentInstall)))
	mux.Handle("GET /api/setup-jobs/{id}", api.auth(http.HandlerFunc(api.setupJobStatus)))
	mux.Handle("POST /api/servers/{id}/adopt", api.auth(http.HandlerFunc(api.adoptExisting)))
	mux.Handle("PUT /api/servers/{id}", api.auth(http.HandlerFunc(api.serverUpdate)))
	mux.Handle("DELETE /api/servers/{id}", api.auth(http.HandlerFunc(api.serverDelete)))
	mux.Handle("/api/apps", api.auth(http.HandlerFunc(api.apps)))
	mux.Handle("POST /api/apps/upload", api.auth(http.HandlerFunc(api.appUpload)))
	mux.Handle("POST /api/apps/{id}/deploy", api.auth(http.HandlerFunc(api.appDeploy)))
	mux.Handle("GET /api/apps/{id}/variables", api.auth(http.HandlerFunc(api.appVariables)))
	mux.Handle("POST /api/apps/{id}/promote", api.auth(http.HandlerFunc(api.promoteAdoptedApp)))
	mux.Handle("PUT /api/apps/{id}/config", api.auth(http.HandlerFunc(api.appConfig)))
	mux.Handle("PUT /api/apps/{id}/adopted-domains", api.auth(http.HandlerFunc(api.adoptedDomainsUpdate)))
	mux.Handle("DELETE /api/apps/{id}", api.auth(http.HandlerFunc(api.appDelete)))
	mux.Handle("/api/databases", api.auth(http.HandlerFunc(api.databases)))
	mux.Handle("POST /api/databases/{id}/provision", api.auth(http.HandlerFunc(api.databaseProvision)))
	mux.Handle("PUT /api/databases/{id}", api.auth(http.HandlerFunc(api.databaseUpdate)))
	mux.Handle("DELETE /api/databases/{id}", api.auth(http.HandlerFunc(api.databaseDelete)))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(assets)))

	listen := os.Getenv("MINIPAAS_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:9080"
	}
	server := &http.Server{Addr: listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Minute, WriteTimeout: 20 * time.Minute, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	go api.runGitAutoDeploy()
	log.Printf("MiniPaaS listening on http://%s", listen)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

var _ = strconv.Itoa
