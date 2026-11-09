package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 核心回归：部署失败会留下一个比成功部署更新的镜像 tag，
// 清理时必须按「成功部署记录」而不是 tag 数字来保护镜像。
func TestProtectedImagesUsesSuccessfulDeployments(t *testing.T) {
	base := time.Now()
	state := State{Apps: []App{{
		ID: "app_1", ServerID: "srv_1", Name: "jiexi520",
		Image: "localhost/minipaas/jiexi520-ab12:300",
		Revisions: []DeploymentRevision{
			{Image: "localhost/minipaas/jiexi520-ab12:100", DeployedAt: base.Add(-3 * time.Hour), Reason: "部署成功"},
			{Image: "localhost/minipaas/jiexi520-ab12:200", DeployedAt: base.Add(-2 * time.Hour), Reason: "部署成功"},
			{Image: "localhost/minipaas/jiexi520-ab12:300", DeployedAt: base.Add(-1 * time.Hour), Reason: "部署成功"},
		},
	}}}
	protected, byApp := protectedImages(state, "srv_1", 2)
	wanted := map[string]bool{
		"localhost/minipaas/jiexi520-ab12:300": true, // 当前运行
		"localhost/minipaas/jiexi520-ab12:200": true, // 最近第二次成功
	}
	if len(protected) != len(wanted) {
		t.Fatalf("保护镜像数量 = %d (%v)，期望 %d", len(protected), protected, len(wanted))
	}
	for _, image := range protected {
		if !wanted[image] {
			t.Fatalf("不该保护的镜像被保护了: %s", image)
		}
	}
	if byApp["jiexi520"] != "localhost/minipaas/jiexi520-ab12:300" {
		t.Fatalf("当前镜像记录错误: %v", byApp)
	}
	// 失败构建产生的 301/302 不在 state 里，自然不会被保护
	for _, failed := range []string{"localhost/minipaas/jiexi520-ab12:301", "localhost/minipaas/jiexi520-ab12:302"} {
		for _, image := range protected {
			if image == failed {
				t.Fatalf("失败的构建镜像不应被保护: %s", failed)
			}
		}
	}
}

func TestProtectedImagesIsolatesServersAndAdoptedApps(t *testing.T) {
	state := State{Apps: []App{
		{ID: "a1", ServerID: "srv_1", Name: "one", Image: "localhost/minipaas/one-aa:1"},
		{ID: "a2", ServerID: "srv_2", Name: "two", Image: "localhost/minipaas/two-bb:1"},
		{ID: "a3", ServerID: "srv_1", Name: "adopted", ManagedMode: "adopted", Image: "localhost/minipaas/adopted-cc:1"},
	}}
	protected, _ := protectedImages(state, "srv_1", 2)
	if len(protected) != 1 || protected[0] != "localhost/minipaas/one-aa:1" {
		t.Fatalf("按服务器隔离或跳过接管应用失败: %v", protected)
	}
}

func TestProtectedImagesKeepsAtLeastOne(t *testing.T) {
	state := State{Apps: []App{{ID: "a1", ServerID: "srv_1", Name: "one", Image: "localhost/minipaas/one-aa:7"}}}
	protected, _ := protectedImages(state, "srv_1", 0)
	if len(protected) != 1 || protected[0] != "localhost/minipaas/one-aa:7" {
		t.Fatalf("保留次数为 0 时也必须保护当前镜像: %v", protected)
	}
}

func TestCleanupRecoveryPackagesKeepsNewestAndLatestLink(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"2026-11-05_03-30-00", "2026-11-06_03-30-00", "2026-11-07_03-30-00", "2026-11-08_03-30-00"} {
		if err := os.MkdirAll(filepath.Join(root, id), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "images"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "2026-11-07_03-30-00"), filepath.Join(root, "latest")); err != nil {
		t.Skip("当前系统不支持创建软链")
	}
	removed, err := cleanupRecoveryPackages(root, 1)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if len(removed) != 2 {
		t.Fatalf("应删除 2 个旧备份（latest 指向的那份保留），实际 %v", removed)
	}
	for _, keep := range []string{"2026-11-08_03-30-00", "2026-11-07_03-30-00", "images"} {
		if _, err := os.Stat(filepath.Join(root, keep)); err != nil {
			t.Fatalf("%s 不应被删除: %v", keep, err)
		}
	}
	for _, gone := range []string{"2026-11-05_03-30-00", "2026-11-06_03-30-00"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s 应已删除", gone)
		}
	}
}

func TestCleanupRecoveryPackagesDisabled(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "2026-11-08_03-30-00"), 0755); err != nil {
		t.Fatal(err)
	}
	removed, err := cleanupRecoveryPackages(root, 0)
	if err != nil || len(removed) != 0 {
		t.Fatalf("保留数为 0 时不应删除任何备份: %v %v", removed, err)
	}
}

func TestIsLocalServer(t *testing.T) {
	if !isLocalServer(Server{Host: "127.0.0.1"}) {
		t.Fatal("127.0.0.1 应判定为本机")
	}
	if !isLocalServer(Server{Host: "localhost"}) {
		t.Fatal("localhost 应判定为本机")
	}
	if isLocalServer(Server{Host: "203.0.113.9"}) {
		t.Fatal("外部地址不应判定为本机")
	}
}

func TestParseMaintenanceOutput(t *testing.T) {
	output := "已删除旧镜像 localhost/minipaas/x:1\nMINIPAAS_MAINT total=5 deleted=3 disk_pct=41 avail_kb=41943040 before_kb=39845888\n"
	total, deleted, pct, avail, before := parseMaintenanceOutput(output)
	if total != 5 || deleted != 3 || pct != 41 || avail != 41943040 || before != 39845888 {
		t.Fatalf("解析结果错误: %d %d %d %d %d", total, deleted, pct, avail, before)
	}
}

func TestMaintenanceSettingsNormalize(t *testing.T) {
	settings := normalizeMaintenanceSettings(MaintenanceSettings{KeepSuccessImages: 0, IntervalHours: 0, KeepRecoveryPackages: -5})
	if settings.KeepSuccessImages != 1 || settings.IntervalHours != 1 || settings.KeepRecoveryPackages != 0 {
		t.Fatalf("默认值归一化失败: %+v", settings)
	}
	settings = normalizeMaintenanceSettings(MaintenanceSettings{KeepSuccessImages: 99, IntervalHours: 99999, KeepRecoveryPackages: 999})
	if settings.KeepSuccessImages != 10 || settings.IntervalHours != 720 || settings.KeepRecoveryPackages != 60 {
		t.Fatalf("上限归一化失败: %+v", settings)
	}
}

func TestMaintenanceStorePersistsDefaults(t *testing.T) {
	dir := t.TempDir()
	store := openMaintenanceStore(dir)
	settings := store.Snapshot()
	if !settings.Enabled || settings.KeepSuccessImages != 2 {
		t.Fatalf("首次打开应启用默认策略: %+v", settings)
	}
	if err := store.Update(func(s *MaintenanceSettings) { s.KeepSuccessImages = 4; s.Enabled = false }); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	reopened := openMaintenanceStore(dir).Snapshot()
	if reopened.KeepSuccessImages != 4 || reopened.Enabled {
		t.Fatalf("重新加载后设置丢失: %+v", reopened)
	}
	if _, err := os.Stat(filepath.Join(dir, maintenanceFileName)); err != nil {
		t.Fatalf("设置文件未写入: %v", err)
	}
}
