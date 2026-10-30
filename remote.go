package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateSSHAddress(host string, port int, user string) error {
	if net.ParseIP(host) == nil && !hostPattern.MatchString(host) {
		return errors.New("主机名格式不正确")
	}
	if port < 1 || port > 65535 {
		return errors.New("SSH 端口不正确")
	}
	if !userPattern.MatchString(user) {
		return errors.New("SSH 用户名格式不正确")
	}
	return nil
}

type RemoteClient struct {
	Server          Server
	PrivateKey      []byte
	ObservedHostKey string
}
type RemoteInfo struct {
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	CPU                int    `json:"cpu"`
	MemoryMB           int    `json:"memoryMB"`
	DiskGB             int    `json:"diskGB"`
	K3sVersion         string `json:"k3sVersion,omitempty"`
	HostKeyFingerprint string `json:"hostKeyFingerprint,omitempty"`
}

func (r *RemoteClient) dial(ctx context.Context) (*ssh.Client, error) {
	var auth ssh.AuthMethod
	if r.Server.AuthType == "password" {
		if len(r.PrivateKey) == 0 {
			return nil, errors.New("SSH 密码为空")
		}
		auth = ssh.Password(string(r.PrivateKey))
	} else {
		signer, err := ssh.ParsePrivateKey(r.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	}
	config := &ssh.ClientConfig{User: r.Server.User, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if r.Server.HostKeyFingerprint != "" && r.Server.HostKeyFingerprint != fingerprint {
			return fmt.Errorf("SSH 主机密钥发生变化，期望 %s，实际 %s", r.Server.HostKeyFingerprint, fingerprint)
		}
		r.ObservedHostKey = fingerprint
		return nil
	}, Timeout: 12 * time.Second}
	address := net.JoinHostPort(r.Server.Host, strconv.Itoa(r.Server.Port))
	conn, err := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("连接 SSH 失败: %w", err)
	}
	c, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH 认证失败: %w", err)
	}
	return ssh.NewClient(c, channels, requests), nil
}

func (r *RemoteClient) run(ctx context.Context, command string, timeout time.Duration) (string, error) {
	client, err := r.dial(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	type result struct {
		output []byte
		err    error
	}
	ch := make(chan result, 1)
	go func() { out, runErr := session.CombinedOutput(command); ch <- result{out, runErr} }()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return "", errors.New("远程命令执行超时")
	case result := <-ch:
		return string(result.output), result.err
	}
}

func (r *RemoteClient) Probe(ctx context.Context) (RemoteInfo, error) {
	command := `set -eu
printf '%s\n' "$(hostname)"
. /etc/os-release 2>/dev/null || true; printf '%s\n' "${PRETTY_NAME:-unknown}"
uname -m
nproc
awk '/MemTotal/ {printf "%d\n", $2/1024}' /proc/meminfo
df -BG --output=size / | tail -1 | tr -dc '0-9'; echo
if command -v k3s >/dev/null 2>&1; then k3s --version | head -1 | awk '{print $3}'; else echo none; fi`
	out, err := r.run(ctx, command, 20*time.Second)
	if err != nil {
		return RemoteInfo{}, fmt.Errorf("服务器检测失败: %w (%s)", err, strings.TrimSpace(out))
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 7 {
		return RemoteInfo{}, errors.New("服务器检测返回内容不完整")
	}
	cpu, _ := strconv.Atoi(strings.TrimSpace(lines[3]))
	mem, _ := strconv.Atoi(strings.TrimSpace(lines[4]))
	disk, _ := strconv.Atoi(strings.TrimSpace(lines[5]))
	k3s := strings.TrimSpace(lines[6])
	if k3s == "none" {
		k3s = ""
	}
	return RemoteInfo{Hostname: lines[0], OS: lines[1], Arch: lines[2], CPU: cpu, MemoryMB: mem, DiskGB: disk, K3sVersion: k3s, HostKeyFingerprint: r.ObservedHostKey}, nil
}

func (r *RemoteClient) BootstrapK3s(ctx context.Context) (string, error) {
	command := `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then apt-get update; apt-get install -y curl ca-certificates git jq tar gzip unzip buildah; fi
mkdir -p /etc/containers
touch /etc/containers/registries.conf
sed -i '/^unqualified-search-registries[[:space:]]*=/d' /etc/containers/registries.conf
printf '%s\n' 'unqualified-search-registries = ["docker.io"]' >> /etc/containers/registries.conf
if ! command -v k3s >/dev/null 2>&1; then curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable traefik --write-kubeconfig-mode 600' sh -; fi
systemctl enable --now k3s
for i in $(seq 1 60); do k3s kubectl get node >/dev/null 2>&1 && break; sleep 2; done
for ns in minipaas-system minipaas-apps minipaas-data; do k3s kubectl create namespace "$ns" --dry-run=client -o yaml | k3s kubectl apply -f -; done
printf 'K3s bootstrap complete\n'; k3s --version | head -1; k3s kubectl get node -o wide`
	out, err := r.run(ctx, command, 12*time.Minute)
	if err != nil {
		return out, fmt.Errorf("K3s 引导失败: %w", err)
	}
	return out, nil
}

func (r *RemoteClient) Upload(ctx context.Context, localPath, remotePath string) error {
	client, err := r.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftpClient.Close()
	if err := sftpClient.MkdirAll(filepath.Dir(remotePath)); err != nil {
		return err
	}
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	temporary := remotePath + ".part"
	dst, err := sftpClient.OpenFile(temporary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := sftpClient.PosixRename(temporary, remotePath); err == nil {
		return nil
	}
	// Some SSH servers do not expose the POSIX rename extension. The temporary
	// file is already complete, so fall back to replacing the old upload.
	if err := sftpClient.Remove(remotePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return sftpClient.Rename(temporary, remotePath)
}
