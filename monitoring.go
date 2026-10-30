package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServerMetrics struct {
	ServerID      string    `json:"serverId"`
	Status        string    `json:"status"`
	CPUPercent    int       `json:"cpuPercent"`
	MemoryPercent int       `json:"memoryPercent"`
	MemoryUsedMB  int       `json:"memoryUsedMB"`
	MemoryTotalMB int       `json:"memoryTotalMB"`
	DiskPercent   int       `json:"diskPercent"`
	DiskUsedGB    int       `json:"diskUsedGB"`
	DiskTotalGB   int       `json:"diskTotalGB"`
	Load1         string    `json:"load1"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	PodsReady     int       `json:"podsReady"`
	PodsTotal     int       `json:"podsTotal"`
	Error         string    `json:"error,omitempty"`
	CheckedAt     time.Time `json:"checkedAt"`
}

func parseMetricInt(values map[string]string, key string) int {
	value, _ := strconv.Atoi(values[key])
	return value
}

func collectServerMetrics(ctx context.Context, client RemoteClient) ServerMetrics {
	result := ServerMetrics{ServerID: client.Server.ID, Status: "online", CheckedAt: time.Now()}
	command := `set -eu
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ </proc/stat
t1=$((u1+n1+s1+i1+w1+q1+sq1+st1)); idle1=$((i1+w1)); sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ </proc/stat
t2=$((u2+n2+s2+i2+w2+q2+sq2+st2)); idle2=$((i2+w2)); dt=$((t2-t1)); di=$((idle2-idle1)); [ "$dt" -gt 0 ] && cpu=$(((100*(dt-di))/dt)) || cpu=0
eval "$(awk '/MemTotal/ {t=int($2/1024)} /MemAvailable/ {a=int($2/1024)} END {printf "mem_total=%d mem_used=%d mem_pct=%d",t,t-a,t?((t-a)*100/t):0}' /proc/meminfo)"
set -- $(df -P -BG / | awk 'NR==2 {gsub(/G|%/,"",$2);gsub(/G|%/,"",$3);gsub(/G|%/,"",$5);print $2,$3,$5}')
disk_total=$1; disk_used=$2; disk_pct=$3
load1=$(awk '{print $1}' /proc/loadavg); uptime=$(cut -d. -f1 /proc/uptime)
pods_total=0; pods_ready=0
if command -v k3s >/dev/null 2>&1; then
  pods_total=$(k3s kubectl get pods -A --no-headers 2>/dev/null | wc -l)
  pods_ready=$(k3s kubectl get pods -A --no-headers 2>/dev/null | awk '{split($3,a,"/"); if(a[1]==a[2] && $4=="Running") n++} END{print n+0}')
fi
printf 'cpu=%s\nmem_total=%s\nmem_used=%s\nmem_pct=%s\ndisk_total=%s\ndisk_used=%s\ndisk_pct=%s\nload1=%s\nuptime=%s\npods_total=%s\npods_ready=%s\n' "$cpu" "$mem_total" "$mem_used" "$mem_pct" "$disk_total" "$disk_used" "$disk_pct" "$load1" "$uptime" "$pods_total" "$pods_ready"`
	out, err := client.run(ctx, command, 25*time.Second)
	if err != nil {
		result.Status, result.Error = "offline", err.Error()
		return result
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}
	result.CPUPercent = parseMetricInt(values, "cpu")
	result.MemoryTotalMB, result.MemoryUsedMB, result.MemoryPercent = parseMetricInt(values, "mem_total"), parseMetricInt(values, "mem_used"), parseMetricInt(values, "mem_pct")
	result.DiskTotalGB, result.DiskUsedGB, result.DiskPercent = parseMetricInt(values, "disk_total"), parseMetricInt(values, "disk_used"), parseMetricInt(values, "disk_pct")
	result.Load1 = values["load1"]
	result.UptimeSeconds, _ = strconv.ParseInt(values["uptime"], 10, 64)
	result.PodsTotal, result.PodsReady = parseMetricInt(values, "pods_total"), parseMetricInt(values, "pods_ready")
	return result
}

func (a *API) monitoring(w http.ResponseWriter, r *http.Request) {
	servers := a.store.Snapshot().Servers
	results := make([]ServerMetrics, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(index int, item Server) {
			defer wg.Done()
			key, err := a.secrets.Decrypt(item.Credential)
			if err != nil {
				results[index] = ServerMetrics{ServerID: item.ID, Status: "offline", Error: "无法读取服务器凭据", CheckedAt: time.Now()}
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			results[index] = collectServerMetrics(ctx, RemoteClient{Server: item, PrivateKey: key})
		}(i, server)
	}
	wg.Wait()
	writeJSON(w, 200, results)
}
