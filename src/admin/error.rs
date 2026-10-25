//! Admin API 错误类型定义

use std::fmt;

use axum::http::StatusCode;

use super::types::AdminErrorResponse;

/// Admin 服务错误类型
#[derive(Debug)]
pub enum AdminServiceError {
    /// 凭据不存在
    NotFound { id: u64 },

    /// 上游服务调用失败（网络、API 错误等）
    UpstreamError(String),

    /// 内部状态错误
    InternalError(String),

    /// 凭据无效（验证失败）
    InvalidCredential(String),

    /// 被引用的代理仍在使用中
    Conflict(String),

    /// 存储不可写（单对象格式 / 无保存路径 / 写入失败）
    StorageNotWritable(String),

    /// 按名称/标识定位的资源不存在（代理等）
    NotFoundEntity(String),
}

impl fmt::Display for AdminServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminServiceError::NotFound { id } => {
                write!(f, "凭据不存在: {}", id)
            }
            AdminServiceError::UpstreamError(msg) => write!(f, "上游服务错误: {}", msg),
            AdminServiceError::InternalError(msg) => write!(f, "内部错误: {}", msg),
            AdminServiceError::InvalidCredential(msg) => write!(f, "凭据无效: {}", msg),
            AdminServiceError::Conflict(msg) => write!(f, "{}", msg),
            AdminServiceError::StorageNotWritable(msg) => write!(f, "{}", msg),
            AdminServiceError::NotFoundEntity(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AdminServiceError {}

impl AdminServiceError {
    /// 获取对应的 HTTP 状态码
    pub fn status_code(&self) -> StatusCode {
        match self {
            AdminServiceError::NotFound { .. } => StatusCode::NOT_FOUND,
            AdminServiceError::UpstreamError(_) => StatusCode::BAD_GATEWAY,
            AdminServiceError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AdminServiceError::InvalidCredential(_) => StatusCode::BAD_REQUEST,
            AdminServiceError::Conflict(_) => StatusCode::CONFLICT,
            AdminServiceError::StorageNotWritable(_) => StatusCode::BAD_REQUEST,
            AdminServiceError::NotFoundEntity(_) => StatusCode::NOT_FOUND,
        }
    }

    /// 转换为 API 错误响应
    pub fn into_response(self) -> AdminErrorResponse {
        match &self {
            AdminServiceError::NotFound { .. } => AdminErrorResponse::not_found(self.to_string()),
            AdminServiceError::UpstreamError(_) => AdminErrorResponse::api_error(self.to_string()),
            AdminServiceError::InternalError(_) => {
                AdminErrorResponse::internal_error(self.to_string())
            }
            AdminServiceError::InvalidCredential(_) => {
                AdminErrorResponse::invalid_request(self.to_string())
            }
            AdminServiceError::Conflict(_) => AdminErrorResponse::new("conflict", self.to_string()),
            AdminServiceError::StorageNotWritable(_) => {
                AdminErrorResponse::invalid_request(self.to_string())
            }
            AdminServiceError::NotFoundEntity(_) => AdminErrorResponse::not_found(self.to_string()),
        }
    }
}
