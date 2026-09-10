//! 【每命令资源边界】cgroup v2 manager：Manager trait + ProcessCgroup 叶子 + init 策略。
//! 契约：镜像上游 internal/services/cgroups（iface.go / cgroup2.go / noop.go）。
//! 来源：承接 cgroup/mod.rs（原样迁入）。
//! （PR-1 骨架：实现待 PR-2 搬运迁入）
