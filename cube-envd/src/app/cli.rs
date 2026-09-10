//! Go flag 兼容的命令行解析（-port / -isnotfc / -version / -commit / -h 与用法错误码）。
//!
//! 回答：进程参数怎么解析成 Cli——逐条对齐 Go flag 的行为与退出码。
//! 来源：承接 main.rs 的 parse_cli / split_flag / fail / print_usage。
//! （PR-1 骨架：实现待 PR-2 自 main.rs 迁入）
