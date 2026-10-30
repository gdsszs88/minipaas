#!/usr/bin/env bash
set -euo pipefail

work=/var/lib/minipaas/smoke-test
image=localhost/minipaas/smoke-test:20261030
namespace=minipaas-smoke-test

cleanup() {
  k3s kubectl delete namespace "$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k3s ctr images rm "$image" >/dev/null 2>&1 || true
  buildah rmi "$image" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

rm -rf "$work"
mkdir -p "$work"
cat >"$work/index.html" <<'EOF'
<!doctype html><title>MiniPaaS smoke test</title><h1>ok</h1>
EOF
cat >"$work/Dockerfile" <<'EOF'
FROM docker.io/library/nginx:1.27-alpine
COPY index.html /usr/share/nginx/html/index.html
EOF

buildah bud --isolation chroot -t "$image" "$work"
buildah push "$image" "docker-archive:$work/image.tar:$image"
k3s ctr images import "$work/image.tar"
k3s kubectl create namespace "$namespace"
k3s kubectl -n "$namespace" create deployment smoke --image="$image"
k3s kubectl -n "$namespace" rollout status deployment/smoke --timeout=180s
k3s kubectl -n "$namespace" get pod -l app=smoke -o jsonpath='{.items[0].status.phase}{"\n"}'
echo MINIPAAS_SMOKE_TEST_OK
