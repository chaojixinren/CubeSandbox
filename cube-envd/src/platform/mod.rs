//! 【L2 共享设施】被 ≥2 域消费、自身无 wire 契约的进程级上下文与 OS 接触点。
//! 成员：identity（用户/组解析 + 路径锚定）、config（env / 默认用户 / 默认工作目录 /
//! 令牌 / init 时间戳）。cgroup 不在此：单域独享，归 process/cgroup/。
//! 来源：承接 auth.rs 与 state.rs 的 config/token 部分。
//! （PR-1 骨架：实现待 PR-2 搬运迁入）
