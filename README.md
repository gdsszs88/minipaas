# MiniPaaS

MiniPaaS 是一个部署在自己 VPS 上的轻量可视化 PaaS 面板。它通过 SSH 管理服务器，支持 Git/本地源码部署、K3s、环境变量、域名 HTTPS、PostgreSQL/MySQL/Redis、自动部署、备份与现有工作负载接管。

在面板添加其他 Ubuntu/Debian VPS 后，“初始化环境”会自动安装构建工具、K3s、数据库客户端、独立 Caddy HTTPS 网关并检查 80/443 端口。环境显示“完全就绪”后，即可把应用和数据库远程部署到该服务器。

添加服务器支持 SSH 私钥和 SSH 密码两种登录方式，凭据均加密保存在控制端。应用列表按目标服务器分组并支持筛选，应用卡片会明确标记实际部署服务器。

## 一条命令安装

准备一台全新的 Ubuntu 22.04/24.04 或 Debian 12 x86_64 VPS，并提前把域名的 A 记录解析到服务器公网 IP，然后以 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gdsszs88/minipaas/main/install.sh)
```

脚本会询问面板域名和管理员密码，并自动安装基础依赖、K3s、Caddy HTTPS 网关和 MiniPaaS。安装完成后浏览器访问输出的 HTTPS 地址。

也可以直接传入域名：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gdsszs88/minipaas/main/install.sh) panel.example.com
```

## 管理命令

直接运行 `minipaas` 可打开交互菜单。

```bash
minipaas status                    # 查看状态和面板地址
minipaas logs                      # 实时查看日志
minipaas domain panel2.example.com # 更换面板域名并自动申请 HTTPS
minipaas update                    # 更新到 GitHub 最新版本
minipaas password                  # 交互式修改管理员密码
minipaas restart                   # 重启面板
minipaas uninstall                 # 卸载面板，保留网站、数据库和面板数据
```

## 安全说明

- 面板仅监听 `127.0.0.1:9080`，公网由 Caddy 提供 HTTPS。
- SSH 私钥和应用变量使用本机主密钥加密后保存在 `/var/lib/minipaas`。
- 卸载命令默认保留 K3s、网站、数据库和 `/var/lib/minipaas` 恢复数据。
- 请只在可信服务器上使用，并定期下载独立备份。

## 从源码构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o minipaas-linux-amd64 .
```

项目基于 Go，前端为内嵌的原生 HTML/CSS/JavaScript，无需 Node.js 构建链。
