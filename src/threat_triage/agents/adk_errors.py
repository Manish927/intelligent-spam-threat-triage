from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ADKErrorCategory(str, Enum):
    """
    Normalized error categories for Google ADK / Gemini execution.

    These categories are intentionally platform-oriented rather than
    tied to one specific Google exception hierarchy.
    """

    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR"
    QUOTA_ERROR = "QUOTA_ERROR"
    MODEL_RESPONSE_ERROR = "MODEL_RESPONSE_ERROR"
    TOOL_EXECUTION_ERROR = "TOOL_EXECUTION_ERROR"
    RUNTIME_ERROR = "RUNTIME_ERROR"


@dataclass(frozen=True)
class ADKErrorInfo:
    """
    Safe, normalized description of an ADK/Gemini execution failure.

    This structure is suitable for:
        - application error handling,
        - logs,
        - observability,
        - API responses,
        - tests.

    It must never include API keys or raw secret values.
    """

    category: ADKErrorCategory

    message: str

    retryable: bool

    provider: str = "google"

    status_code: Optional[int] = None

    original_exception_type: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.message:
            raise ValueError(
                "message must not be empty"
            )

        if not self.provider:
            raise ValueError(
                "provider must not be empty"
            )

        if (
            self.status_code is not None
            and self.status_code <= 0
        ):
            raise ValueError(
                "status_code must be positive"
            )


class ADKExecutionError(RuntimeError):
    """
    Base exception raised by the platform for normalized ADK failures.
    """

    def __init__(
        self,
        info: ADKErrorInfo,
    ) -> None:
        self.info = info

        super().__init__(
            info.message
        )

    @property
    def category(
        self,
    ) -> ADKErrorCategory:
        return self.info.category

    @property
    def retryable(
        self,
    ) -> bool:
        return self.info.retryable

    @property
    def status_code(
        self,
    ) -> Optional[int]:
        return self.info.status_code


class ADKAuthenticationError(
    ADKExecutionError
):
    """
    Authentication failed.

    Typical causes:
        - missing API key,
        - invalid API key,
        - revoked credentials.
    """


class ADKPermissionError(
    ADKExecutionError
):
    """
    Authenticated identity lacks permission to use the requested
    Google/Gemini resource.
    """


class ADKRateLimitError(
    ADKExecutionError
):
    """
    Request was throttled because a request-rate limit was exceeded.
    """


class ADKQuotaError(
    ADKExecutionError
):
    """
    Request failed because the configured quota or allocation was
    exhausted.
    """


class ADKModelResponseError(
    ADKExecutionError
):
    """
    Gemini returned no usable response or returned output that violated
    the structured response contract.
    """


class ADKToolExecutionError(
    ADKExecutionError
):
    """
    An agent tool failed during review execution.
    """


class ADKRuntimeError(
    ADKExecutionError
):
    """
    Catch-all runtime error for ADK/Gemini failures that do not map to a
    more specific category.
    """


def build_authentication_error(
    *,
    message: str = (
        "Gemini authentication failed."
    ),
    status_code: Optional[int] = None,
    original_exception: Optional[BaseException] = None,
) -> ADKAuthenticationError:
    return ADKAuthenticationError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .AUTHENTICATION_ERROR
            ),
            message=message,
            retryable=False,
            status_code=status_code,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_permission_error(
    *,
    message: str = (
        "Gemini request was denied by the provider."
    ),
    status_code: Optional[int] = None,
    original_exception: Optional[BaseException] = None,
) -> ADKPermissionError:
    return ADKPermissionError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .PERMISSION_ERROR
            ),
            message=message,
            retryable=False,
            status_code=status_code,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_rate_limit_error(
    *,
    message: str = (
        "Gemini request was rate limited."
    ),
    status_code: Optional[int] = None,
    original_exception: Optional[BaseException] = None,
) -> ADKRateLimitError:
    return ADKRateLimitError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .RATE_LIMIT_ERROR
            ),
            message=message,
            retryable=True,
            status_code=status_code,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_quota_error(
    *,
    message: str = (
        "Gemini quota is unavailable or exhausted."
    ),
    status_code: Optional[int] = None,
    original_exception: Optional[BaseException] = None,
) -> ADKQuotaError:
    return ADKQuotaError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .QUOTA_ERROR
            ),
            message=message,
            retryable=False,
            status_code=status_code,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_model_response_error(
    *,
    message: str = (
        "Gemini returned an invalid model response."
    ),
    original_exception: Optional[BaseException] = None,
) -> ADKModelResponseError:
    return ADKModelResponseError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .MODEL_RESPONSE_ERROR
            ),
            message=message,
            retryable=False,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_tool_execution_error(
    *,
    message: str = (
        "An agent tool failed during execution."
    ),
    original_exception: Optional[BaseException] = None,
) -> ADKToolExecutionError:
    return ADKToolExecutionError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .TOOL_EXECUTION_ERROR
            ),
            message=message,
            retryable=False,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def build_runtime_error(
    *,
    message: str = (
        "Google ADK runtime execution failed."
    ),
    original_exception: Optional[BaseException] = None,
) -> ADKRuntimeError:
    return ADKRuntimeError(
        ADKErrorInfo(
            category=(
                ADKErrorCategory
                .RUNTIME_ERROR
            ),
            message=message,
            retryable=False,
            original_exception_type=(
                _exception_type_name(
                    original_exception
                )
            ),
        )
    )


def _exception_type_name(
    exception: Optional[BaseException],
) -> Optional[str]:
    if exception is None:
        return None

    return type(
        exception
    ).__name__