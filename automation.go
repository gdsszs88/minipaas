package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"time"
)

func (a *API) currentGitCommit(ctx context.Context, app App, server Server, key []byte) (string, error) {
	if app.SourceType != "git" || strings.TrimSpace(app.Repository) == "" {
		return "", nil
	}
	branch := strings.TrimSpace(app.Branch)
	if branch == "" {
		branch = "main"
	}
	script := fmt.Sprintf(`set -e
repo=$(printf '%%s' '%s' | base64 -d)
branch=$(printf '%%s' '%s' | base64 -d)
git ls-remote "$repo" "refs/heads/$branch" | awk 'NR==1 {print $1}'
`, base64.StdEncoding.EncodeToString([]byte(app.Repository)), base64.StdEncoding.EncodeToString([]byte(branch)))
	client := RemoteClient{Server: server, PrivateKey: key}
	output, err := client.run(ctx, script, 45*time.Second)
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(output)
	if fields := strings.Fields(commit); len(fields) > 0 {
		commit = fields[len(fields)-1]
	}
	if len(commit) != 40 && len(commit) != 64 {
		return "", fmt.Errorf("无法读取 Git 分支提交")
	}
	return commit, nil
}

func (a *API) checkGitAutoDeploy() {
	state := a.store.Snapshot()
	for _, app := range state.Apps {
		if !app.AutoDeploy || app.ManagedMode != "" || app.Status == "deploying" {
			continue
		}
		var server Server
		found := false
		for _, item := range state.Servers {
			if item.ID == app.ServerID {
				server, found = item, true
				break
			}
		}
		if !found {
			continue
		}
		key, err := a.secrets.Decrypt(server.Credential)
		if err != nil {
			continue
		}
		if app.SourceType != "git" {
			name := "mp-" + kubeName(app.Name) + "-" + idSuffix(app.ID)
			checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Minute)
			client := RemoteClient{Server: server, PrivateKey: key}
			output, readyErr := client.run(checkCtx, fmt.Sprintf("k3s kubectl -n minipaas-apps get deployment %s -o jsonpath='{.status.readyReplicas}'", name), 45*time.Second)
			checkCancel()
			if readyErr == nil && strings.TrimSpace(output) == "1" {
				continue
			}
			req := httptest.NewRequest("POST", "/api/apps/"+app.ID+"/deploy", nil)
			req.SetPathValue("id", app.ID)
			a.appDeploy(httptest.NewRecorder(), req)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		commit, checkErr := a.currentGitCommit(ctx, app, server, key)
		cancel()
		now := time.Now()
		if checkErr != nil {
			_ = a.store.mutate(func(s *State) error {
				for i := range s.Apps {
					if s.Apps[i].ID == app.ID {
						s.Apps[i].GitCheckedAt, s.Apps[i].AutoDeployError = now, checkErr.Error()
					}
				}
				return nil
			})
			continue
		}
		if app.GitCommit == "" && app.Status == "running" {
			_ = a.store.mutate(func(s *State) error {
				for i := range s.Apps {
					if s.Apps[i].ID == app.ID {
						s.Apps[i].GitCommit, s.Apps[i].GitCheckedAt, s.Apps[i].AutoDeployError = commit, now, ""
					}
				}
				return nil
			})
			continue
		}
		if app.GitCommit == "" {
			req := httptest.NewRequest("POST", "/api/apps/"+app.ID+"/deploy", nil)
			req.SetPathValue("id", app.ID)
			a.appDeploy(httptest.NewRecorder(), req)
			continue
		}
		if commit == app.GitCommit {
			_ = a.store.mutate(func(s *State) error {
				for i := range s.Apps {
					if s.Apps[i].ID == app.ID {
						s.Apps[i].GitCheckedAt, s.Apps[i].AutoDeployError = now, ""
					}
				}
				return nil
			})
			continue
		}
		req := httptest.NewRequest("POST", "/api/apps/"+app.ID+"/deploy", nil)
		req.SetPathValue("id", app.ID)
		response := httptest.NewRecorder()
		a.appDeploy(response, req)
		if response.Code >= 300 {
			_ = a.store.mutate(func(s *State) error {
				for i := range s.Apps {
					if s.Apps[i].ID == app.ID {
						s.Apps[i].GitCheckedAt = now
						s.Apps[i].AutoDeployError = "检测到新提交，但自动部署失败；请查看部署日志"
					}
				}
				return nil
			})
		}
	}
}

func (a *API) runGitAutoDeploy() {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		<-timer.C
		a.checkGitAutoDeploy()
		timer.Reset(2 * time.Minute)
	}
}
