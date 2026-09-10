//! 进程级共享配置：env 变量、默认用户/默认工作目录、存取令牌、init 时间戳闸门。
//!
//! 回答：/init 写入了什么、后续请求与子进程怎么消费它们。
//! 为何在 L2 而不在 app/：文件域数据面要读 default_user/default_workdir 并做令牌闸，
//! 放装配层会造成域 → 装配的反向依赖。
//! 来源：承接 state.rs 的 config/token 部分（env_vars / default_user /
//! default_workdir / access_token / claim_timestamp）。
//! （PR-1 骨架：实现待 PR-2 自 state.rs 迁入）
