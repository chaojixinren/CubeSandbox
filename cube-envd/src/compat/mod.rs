// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! 【L1 Go 基线词汇】与 Go envd 0.5.13 对齐的纯数据 + 纯函数。
//!
//! 回答：为什么错误文案/形状长这样（Go 对照）。
//! 不变量：本目录只放数据表与纯函数——无 I/O、无状态、无决策。
//! 来源：承接 go_compat/（原样迁入）。

pub mod vocab;
