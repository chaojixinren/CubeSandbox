// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! 【L1 wire 字节层】与传输无关的 Connect 协议机制。
//!
//! 回答：客户端↔服务端的字节契约怎么编解码、流式响应怎么投递、
//! 心跳与期限怎么解析、错误响应体长什么样。
//! 依赖：仅向下依赖 compat（error.rs 借用 Go 文案表）。
//! 来源：承接 connect.rs（帧/投递/心跳/期限）与 error.rs（错误类型与映射）。
//!
//! 一个文件一个问题：`frames` 帧编解码 / `stream` 流式投递 /
//! `keepalive` 心跳 / `timeout` 期限 / `error` 错误类型与 HTTP 映射。

pub mod error;
pub mod frames;
pub mod keepalive;
pub mod stream;
pub mod timeout;

pub use error::{ConnectCode, ConnectError, RestError};
pub use frames::{
    check_json_codec, decode_single_envelope, end_stream_error, end_stream_ok, message_frame,
    EnvelopeDecoder, MAX_ENVELOPE_SIZE, STREAM_CONTENT_TYPE,
};
pub use keepalive::keepalive_interval_from_headers;
pub use timeout::timeout_from_headers;
