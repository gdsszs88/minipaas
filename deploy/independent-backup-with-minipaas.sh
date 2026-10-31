#!/usr/bin/env bash
set -euo pipefail

backup_root=/root/independent-backups
retention_count=7

cleanup_old_backups() {
  local expired_name expired_path
  local -a expired_backups

  mapfile -t expired_backups < <(
    find "$backup_root" -mindepth 1 -maxdepth 1 -type d \
      -regextype posix-extended \
      -regex '.*/[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}' \
      -printf '%f\n' \
    | sort -r \
    | tail -n "+$((retention_count + 1))"
  )

  for expired_name in "${expired_backups[@]}"; do
    expired_path="$backup_root/$expired_name"
    case "$expired_path" in
      "$backup_root"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_[0-9][0-9]-[0-9][0-9]-[0-9][0-9])
        echo "Removing expired VPS backup: $expired_path"
        rm -rf -- "$expired_path"
        ;;
    esac
  done
}

if [ "${1:-}" = "--cleanup-only" ]; then
  cleanup_old_backups
  exit 0
fi

stamp=$(date +%F_%H-%M-%S)
target="$backup_root/$stamp"

umask 077
mkdir -p "$target/databases" "$target/manifests" "$target/system" "$target/images"

kubectl get namespace,deployment,statefulset,daemonset,service,ingress,pvc,pv,configmap,secret -A -o yaml \
  > "$target/manifests/cluster-resources.yaml"

while IFS='|' read -r namespace pod; do
  [ -n "$namespace" ] || continue
  kubectl exec -n "$namespace" "$pod" -- sh -lc \
    'exec pg_dumpall -U "${POSTGRES_USER:-postgres}"' \
    > "$target/databases/${namespace}-${pod}-postgres.sql"
done < <(
  kubectl get pods -A \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' \
  | awk -F'|' '$3 ~ /(^|\/)postgres:/ { print $1 "|" $2 }'
)

while IFS='|' read -r namespace pod; do
  [ -n "$namespace" ] || continue
  kubectl exec -n "$namespace" "$pod" -- sh -lc \
    'exec mysqldump --single-transaction -u"${MYSQL_USER:-root}" -p"${MYSQL_PASSWORD:-$MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}"' \
    > "$target/databases/${namespace}-${pod}-mysql.sql"
done < <(
  kubectl get pods -A \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' \
  | awk -F'|' '$3 ~ /(^|\/)mysql:/ { print $1 "|" $2 }'
)

while IFS='|' read -r namespace pod; do
  [ -n "$namespace" ] || continue
  kubectl exec -n "$namespace" "$pod" -- sh -lc \
    'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning SAVE >/dev/null'
  kubectl cp "$namespace/$pod:/data/dump.rdb" \
    "$target/databases/${namespace}-${pod}-redis.rdb"
done < <(
  kubectl get pods -A \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' \
  | awk -F'|' '$3 ~ /(^|\/)redis:/ { print $1 "|" $2 }'
)

if [ -d /var/lib/minipaas ] && [ -f /var/lib/minipaas/master.key ]; then
  tar -czf "$target/system/minipaas-control-plane.tar.gz" \
    /var/lib/minipaas \
    /etc/minipaas \
    /opt/minipaas/minipaas \
    /etc/systemd/system/minipaas.service
fi

cp -a /etc/independent-deploy.d "$target/system/" 2>/dev/null || true
cp -a /usr/local/sbin/deploy-all-sites "$target/system/" 2>/dev/null || true
cp -a /usr/local/sbin/independent-k3s-firewall "$target/system/" 2>/dev/null || true
cp -a /etc/systemd/system/deploy-all-sites.service "$target/system/" 2>/dev/null || true
cp -a /etc/systemd/system/deploy-all-sites.timer "$target/system/" 2>/dev/null || true
cp -a /etc/systemd/system/independent-k3s-firewall.service "$target/system/" 2>/dev/null || true
cp -a /root/independent-migration/image-map.tsv "$target/system/" 2>/dev/null || true

mapfile -t managed_images < <(
  {
    k3s ctr -n k8s.io images list -q | grep '^localhost/minipaas/' || true
    kubectl -n minipaas-apps get deployments -o jsonpath='{range .items[*].spec.template.spec.containers[*]}{.image}{"\n"}{end}' 2>/dev/null || true
  } | sed '/^$/d' | sort -u
)
if [ "${#managed_images[@]}" -gt 0 ]; then
  k3s ctr -n k8s.io images export "$target/images/minipaas-managed-images.tar" "${managed_images[@]}"
fi

(
  cd "$target"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum
) > "$target/SHA256SUMS"

chmod -R go-rwx "$target"
ln -sfn "$target" "$backup_root/latest"

# Keep only the newest recovery packages on the VPS. Off-server Windows
# copies are not affected by this cleanup.
cleanup_old_backups
