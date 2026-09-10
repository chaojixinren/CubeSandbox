//! 磁盘元数据 → wire 上的 EntryInfo 映射（类型 / 权限 / 时间 / 属主 / 符号链接）。
//!
//! 来源：承接 msg/filesystem.rs 的 entry_info / file_type_of /
//! permissions_string / rfc3339_nanos 与属主查表。
//! （PR-1 骨架：实现待 PR-2 自 msg/filesystem.rs 迁入）
