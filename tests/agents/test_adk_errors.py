import pytest

from threat_triage.agents.adk_errors import (
    ADKAuthenticationError,
    ADKErrorCategory,
    ADKErrorInfo,
    ADKExecutionError,
    ADKModelResponseError,
    ADKPermissionError,
    ADKQuotaError,
    ADKRateLimitError,
    ADKRuntimeError,
    ADKToolExecutionError,
    build_authentication_error,
    build_model_response_error,
    build_permission_error,
    build_quota_error,
    build_rate_limit_error,
    build_runtime_error,
    build_tool_execution_error,
)


def test_error_categories_are_stable():
    assert (
        ADKErrorCategory.AUTHENTICATION_ERROR.value
        == "AUTHENTICATION_ERROR"
    )

    assert (
        ADKErrorCategory.PERMISSION_ERROR.value
        == "PERMISSION_ERROR"
    )

    assert (
        ADKErrorCategory.RATE_LIMIT_ERROR.value
        == "RATE_LIMIT_ERROR"
    )

    assert (
        ADKErrorCategory.QUOTA_ERROR.value
        == "QUOTA_ERROR"
    )

    assert (
        ADKErrorCategory.MODEL_RESPONSE_ERROR.value
        == "MODEL_RESPONSE_ERROR"
    )

    assert (
        ADKErrorCategory.TOOL_EXECUTION_ERROR.value
        == "TOOL_EXECUTION_ERROR"
    )

    assert (
        ADKErrorCategory.RUNTIME_ERROR.value
        == "RUNTIME_ERROR"
    )


def test_error_info_creation():
    info = ADKErrorInfo(
        category=ADKErrorCategory.PERMISSION_ERROR,
        message="Permission denied",
        retryable=False,
        provider="google",
        status_code=403,
        original_exception_type="ClientError",
    )

    assert (
        info.category
        == ADKErrorCategory.PERMISSION_ERROR
    )

    assert (
        info.message
        == "Permission denied"
    )

    assert info.retryable is False

    assert (
        info.provider
        == "google"
    )

    assert (
        info.status_code
        == 403
    )

    assert (
        info.original_exception_type
        == "ClientError"
    )


def test_error_info_rejects_empty_message():
    with pytest.raises(
        ValueError,
        match="message must not be empty",
    ):
        ADKErrorInfo(
            category=ADKErrorCategory.RUNTIME_ERROR,
            message="",
            retryable=False,
        )


def test_error_info_rejects_empty_provider():
    with pytest.raises(
        ValueError,
        match="provider must not be empty",
    ):
        ADKErrorInfo(
            category=ADKErrorCategory.RUNTIME_ERROR,
            message="Runtime failure",
            retryable=False,
            provider="",
        )


@pytest.mark.parametrize(
    "status_code",
    [
        0,
        -1,
        -500,
    ],
)
def test_error_info_rejects_invalid_status_code(
    status_code,
):
    with pytest.raises(
        ValueError,
        match="status_code must be positive",
    ):
        ADKErrorInfo(
            category=ADKErrorCategory.RUNTIME_ERROR,
            message="Runtime failure",
            retryable=False,
            status_code=status_code,
        )


def test_base_execution_error_exposes_info():
    info = ADKErrorInfo(
        category=ADKErrorCategory.RUNTIME_ERROR,
        message="Runtime failed",
        retryable=False,
    )

    error = ADKExecutionError(
        info
    )

    assert (
        error.info
        is info
    )

    assert (
        str(error)
        == "Runtime failed"
    )

    assert (
        error.category
        == ADKErrorCategory.RUNTIME_ERROR
    )

    assert (
        error.retryable
        is False
    )

    assert (
        error.status_code
        is None
    )


def test_build_authentication_error():
    error = build_authentication_error(
        status_code=401,
    )

    assert isinstance(
        error,
        ADKAuthenticationError,
    )

    assert (
        error.category
        == ADKErrorCategory.AUTHENTICATION_ERROR
    )

    assert (
        error.retryable
        is False
    )

    assert (
        error.status_code
        == 401
    )


def test_build_permission_error():
    error = build_permission_error(
        status_code=403,
    )

    assert isinstance(
        error,
        ADKPermissionError,
    )

    assert (
        error.category
        == ADKErrorCategory.PERMISSION_ERROR
    )

    assert (
        error.retryable
        is False
    )

    assert (
        error.status_code
        == 403
    )


def test_build_rate_limit_error_is_retryable():
    error = build_rate_limit_error(
        status_code=429,
    )

    assert isinstance(
        error,
        ADKRateLimitError,
    )

    assert (
        error.category
        == ADKErrorCategory.RATE_LIMIT_ERROR
    )

    assert (
        error.retryable
        is True
    )

    assert (
        error.status_code
        == 429
    )


def test_build_quota_error():
    error = build_quota_error(
        status_code=429,
    )

    assert isinstance(
        error,
        ADKQuotaError,
    )

    assert (
        error.category
        == ADKErrorCategory.QUOTA_ERROR
    )

    assert (
        error.retryable
        is False
    )


def test_build_model_response_error():
    error = build_model_response_error()

    assert isinstance(
        error,
        ADKModelResponseError,
    )

    assert (
        error.category
        == ADKErrorCategory.MODEL_RESPONSE_ERROR
    )

    assert (
        error.retryable
        is False
    )


def test_build_tool_execution_error():
    error = build_tool_execution_error()

    assert isinstance(
        error,
        ADKToolExecutionError,
    )

    assert (
        error.category
        == ADKErrorCategory.TOOL_EXECUTION_ERROR
    )

    assert (
        error.retryable
        is False
    )


def test_build_runtime_error():
    error = build_runtime_error()

    assert isinstance(
        error,
        ADKRuntimeError,
    )

    assert (
        error.category
        == ADKErrorCategory.RUNTIME_ERROR
    )

    assert (
        error.retryable
        is False
    )


def test_original_exception_type_is_preserved():
    original = TimeoutError(
        "provider timeout"
    )

    error = build_runtime_error(
        original_exception=original
    )

    assert (
        error.info.original_exception_type
        == "TimeoutError"
    )


def test_original_exception_message_is_not_automatically_exposed():
    """
    Raw provider exception text may contain sensitive information.

    Builders should preserve only the exception type unless the caller
    deliberately supplies a safe message.
    """

    original = RuntimeError(
        "secret-token=abc123"
    )

    error = build_runtime_error(
        original_exception=original
    )

    assert (
        "secret-token"
        not in str(error)
    )

    assert (
        "abc123"
        not in str(error)
    )

    assert (
        error.info.original_exception_type
        == "RuntimeError"
    )


def test_custom_safe_message_is_preserved():
    error = build_permission_error(
        message=(
            "Gemini project access is denied."
        ),
        status_code=403,
    )

    assert (
        str(error)
        == "Gemini project access is denied."
    )


def test_authentication_error_is_execution_error():
    error = build_authentication_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_permission_error_is_execution_error():
    error = build_permission_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_rate_limit_error_is_execution_error():
    error = build_rate_limit_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_quota_error_is_execution_error():
    error = build_quota_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_model_response_error_is_execution_error():
    error = build_model_response_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_tool_execution_error_is_execution_error():
    error = build_tool_execution_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_runtime_error_is_execution_error():
    error = build_runtime_error()

    assert isinstance(
        error,
        ADKExecutionError,
    )


def test_default_provider_is_google():
    error = build_runtime_error()

    assert (
        error.info.provider
        == "google"
    )


def test_permission_error_can_represent_real_403_case():
    """
    Regression contract for errors such as:

        403 PERMISSION_DENIED
        Your project has been denied access.

    The raw provider response should not be required by downstream
    application code.
    """

    original = RuntimeError(
        "403 PERMISSION_DENIED: "
        "Your project has been denied access."
    )

    error = build_permission_error(
        message=(
            "Gemini project access is denied."
        ),
        status_code=403,
        original_exception=original,
    )

    assert (
        error.category
        == ADKErrorCategory.PERMISSION_ERROR
    )

    assert (
        error.status_code
        == 403
    )

    assert (
        error.retryable
        is False
    )

    assert (
        error.info.original_exception_type
        == "RuntimeError"
    )

    assert (
        "Your project has been denied access"
        not in str(error)
    )