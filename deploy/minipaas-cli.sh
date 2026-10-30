#!/usr/bin/env bash
set -euo pipefail

REPO="${MINIPAAS_REPO:-gdsszs88/minipaas}"
BIN_URL="https://github.com/${REPO}/releases/latest/download/minipaas-linux-amd64"
DOMAIN_FILE=/etc/minipaas/domain
PASSWORD_FILE=/etc/minipaas/admin-password
CADDY_CM=independent-caddy-config
CADDY_DS=independent-caddy

say(){ printf '\033[1;35m[MiniPaaS]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m错误：%s\033[0m\n' "$*" >&2; exit 1; }
need_root(){ [ "$(id -u)" = 0 ] || die "请使用 root 用户运行"; }
valid_domain(){ [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && [[ "$1" == *.* ]]; }
ask(){ local prompt="$1" value="${2:-}"; if [ -t 0 ]; then read -r -p "$prompt" value; elif [ -r /dev/tty ]; then read -r -p "$prompt" value </dev/tty; fi; printf '%s' "$value"; }
ask_secret(){ local value=""; if [ -r /dev/tty ]; then read -r -s -p "设置管理员密码（留空自动生成）: " value </dev/tty; printf '\n' >/dev/tty; fi; printf '%s' "$value"; }

ensure_k3s(){
  if command -v k3s >/dev/null 2>&1; then say "K3s 已安装，跳过"; return; fi
  say "安装 K3s…"
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable traefik --write-kubeconfig-mode 600' sh -
}

ensure_caddy(){
  if k3s kubectl -n default get configmap "$CADDY_CM" >/dev/null 2>&1 && k3s kubectl -n default get daemonset "$CADDY_DS" >/dev/null 2>&1; then say "独立 Caddy 已安装，跳过"; return; fi
  say "安装独立 Caddy HTTPS 网关…"
  install -d -m 700 /var/lib/independent-caddy/data /var/lib/independent-caddy/config
  if ! k3s kubectl -n default get configmap "$CADDY_CM" >/dev/null 2>&1; then
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
spec:
  selector:
    matchLabels:
      app: independent-caddy
  template:
    metadata:
      labels:
        app: independent-caddy
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: caddy
        image: caddy:2-alpine
        args: ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
        volumeMounts:
        - name: config
          mountPath: /etc/caddy
          readOnly: true
        - name: data
          mountPath: /data
        - name: runtime-config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: independent-caddy-config
      - name: data
        hostPath:
          path: /var/lib/independent-caddy/data
          type: DirectoryOrCreate
      - name: runtime-config
        hostPath:
          path: /var/lib/independent-caddy/config
          type: DirectoryOrCreate
YAML
  k3s kubectl apply -f /tmp/minipaas-caddy-daemonset.yaml
  k3s kubectl -n default rollout status daemonset "$CADDY_DS" --timeout=180s
  if ufw status 2>/dev/null | grep -q '^Status: active'; then ufw allow 80/tcp; ufw allow 443/tcp; ufw allow 443/udp; fi
}

write_domain(){
  local domain="$1" file=/tmp/Caddyfile.minipaas new=/tmp/Caddyfile.minipaas.new
  valid_domain "$domain" || die "域名格式不正确：$domain"
  k3s kubectl -n default get configmap "$CADDY_CM" -o jsonpath='{.data.Caddyfile}' >"$file"
  awk '/# BEGIN MINIPAAS PANEL/{skip=1;next}/# END MINIPAAS PANEL/{skip=0;next}!skip{print}' "$file" >"$new"
  cat >>"$new" <<EOF

# BEGIN MINIPAAS PANEL
http://${domain}, https://${domain} {
  encode zstd gzip
  reverse_proxy 127.0.0.1:9080
}
# END MINIPAAS PANEL
EOF
  k3s kubectl -n default create configmap "$CADDY_CM" --from-file=Caddyfile="$new" --dry-run=client -o yaml | k3s kubectl apply -f -
  k3s kubectl -n default rollout restart daemonset "$CADDY_DS"
  k3s kubectl -n default rollout status daemonset "$CADDY_DS" --timeout=180s
  printf '%s\n' "$domain" >"$DOMAIN_FILE"; chmod 600 "$DOMAIN_FILE"
}

download_binary(){
  local tmp=/opt/minipaas/minipaas.new
  say "下载最新 MiniPaaS Linux 版本…"
  curl -fL --retry 3 "$BIN_URL" -o "$tmp"
  chmod 0755 "$tmp"
  file "$tmp" | grep -q 'ELF 64-bit' || die "下载的程序格式不正确"
  mv -f "$tmp" /opt/minipaas/minipaas
}

install_panel(){
  need_root
  [ "$(uname -m)" = x86_64 ] || die "当前安装包仅支持 x86_64/amd64"
  command -v apt-get >/dev/null 2>&1 || die "当前版本支持 Ubuntu/Debian"
  local domain="${1:-}" password="${MINIPAAS_ADMIN_PASSWORD:-}"
  [ -n "$domain" ] || domain="$(ask '请输入面板域名（需提前解析到本机 IP）: ')"
  valid_domain "$domain" || die "域名格式不正确"
  say "安装基础依赖…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl ca-certificates git jq tar gzip unzip rsync openssl file
  ensure_k3s
  ensure_caddy
  install -d -m 700 /etc/minipaas /var/lib/minipaas /opt/minipaas
  download_binary
  if [ ! -s "$PASSWORD_FILE" ]; then
    [ -n "$password" ] || password="$(ask_secret)"
    [ -n "$password" ] || password="$(openssl rand -hex 14)"
    printf '%s' "$password" >"$PASSWORD_FILE"; chmod 600 "$PASSWORD_FILE"
  else password="$(cat "$PASSWORD_FILE")"; fi
  cat >/etc/minipaas/minipaas.env <<EOF
MINIPAAS_ADMIN_PASSWORD_FILE=${PASSWORD_FILE}
MINIPAAS_LISTEN=127.0.0.1:9080
MINIPAAS_DATA_DIR=/var/lib/minipaas
MINIPAAS_SESSION_TTL=24h
EOF
  chmod 600 /etc/minipaas/minipaas.env
  cat >/etc/systemd/system/minipaas.service <<'EOF'
[Unit]
Description=MiniPaaS self-hosted control plane
After=network-online.target k3s.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/minipaas/minipaas.env
ExecStart=/opt/minipaas/minipaas
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/minipaas /root/independent-backups
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now minipaas
  sleep 2
  curl -fsS http://127.0.0.1:9080/api/health >/dev/null || die "面板服务健康检查失败"
  write_domain "$domain"
  say "安装完成： https://${domain}"
  printf '管理员密码：%s\n' "$password"
  say "以后直接运行 minipaas 打开管理菜单"
}

change_domain(){ need_root; [ -s "$DOMAIN_FILE" ] || die "尚未安装 MiniPaaS"; local domain="${1:-}"; [ -n "$domain" ] || domain="$(ask '请输入新域名: ')"; write_domain "$domain"; say "域名已切换为 https://${domain}"; }
update_panel(){ need_root; download_binary; systemctl restart minipaas; sleep 2; curl -fsS http://127.0.0.1:9080/api/health >/dev/null; say "MiniPaaS 已更新并重启"; }
status_panel(){ systemctl status minipaas --no-pager -l || true; [ -s "$DOMAIN_FILE" ] && printf '\n面板地址：https://%s\n' "$(cat "$DOMAIN_FILE")"; }
reset_password(){ need_root; local password="${1:-}"; [ -n "$password" ] || password="$(ask_secret)"; [ -n "$password" ] || die "密码不能为空"; printf '%s' "$password" >"$PASSWORD_FILE"; chmod 600 "$PASSWORD_FILE"; rm -f /var/lib/minipaas/admin-password.sha256; systemctl restart minipaas; say "管理员密码已修改"; }
uninstall_panel(){
  need_root
  local answer="${1:-}"; [ "$answer" = --yes ] || answer="$(ask '确认卸载 MiniPaaS？应用和数据库不会删除 [y/N]: ')"; [[ "$answer" =~ ^(--yes|y|Y)$ ]] || { say "已取消"; return; }
  if k3s kubectl -n default get configmap "$CADDY_CM" >/dev/null 2>&1; then
    local file=/tmp/Caddyfile.minipaas new=/tmp/Caddyfile.minipaas.new
    k3s kubectl -n default get configmap "$CADDY_CM" -o jsonpath='{.data.Caddyfile}' >"$file"
    awk '/# BEGIN MINIPAAS PANEL/{skip=1;next}/# END MINIPAAS PANEL/{skip=0;next}!skip{print}' "$file" >"$new"
    k3s kubectl -n default create configmap "$CADDY_CM" --from-file=Caddyfile="$new" --dry-run=client -o yaml | k3s kubectl apply -f -
    k3s kubectl -n default rollout restart daemonset "$CADDY_DS" >/dev/null
  fi
  systemctl disable --now minipaas 2>/dev/null || true
  rm -f /etc/systemd/system/minipaas.service /opt/minipaas/minipaas
  systemctl daemon-reload
  say "面板程序已卸载；/var/lib/minipaas 数据、K3s、网站和数据库均已保留"
  say "如确定不要面板备份数据，可手动执行：rm -rf /var/lib/minipaas /etc/minipaas"
}

menu(){
  printf '\nMiniPaaS 管理菜单\n1) 查看状态\n2) 修改域名\n3) 更新面板\n4) 修改管理员密码\n5) 查看日志\n6) 卸载面板\n0) 退出\n'
  local choice="$(ask '请选择: ')"
  case "$choice" in 1) status_panel;; 2) change_domain;; 3) update_panel;; 4) reset_password;; 5) journalctl -u minipaas -f;; 6) uninstall_panel;; 0) exit 0;; *) die "无效选项";; esac
}

case "${1:-menu}" in
  install) shift; install_panel "$@";;
  domain) shift; change_domain "$@";;
  status) status_panel;;
  logs) journalctl -u minipaas -f;;
  update) update_panel;;
  password) shift; reset_password "$@";;
  restart) need_root; systemctl restart minipaas; say "已重启";;
  uninstall) shift; uninstall_panel "$@";;
  menu|'') menu;;
  *) printf '用法：minipaas {install [域名]|domain [新域名]|status|logs|update|password [新密码]|restart|uninstall}\n'; exit 1;;
esac
