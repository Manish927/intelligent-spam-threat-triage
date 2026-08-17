import pytest
from pydantic import ValidationError

from threat_triage.agents.adk_runtime import (
    ADKAgentFinding,
    ADKAgentModelMetadata,
    ADKAgentRecommendation,
    ADKAgentReviewResult,
    create_message_review_agent,
    get_agent_runtime_metadata,
)
from threat_triage.agents.message_review_agent import (
    AGENT_NAME,
    AGENT_VERSION,
    MESSAGE_REVIEW_INSTRUCTION,
    get_message_review_tool_functions,
)


def test_runtime_metadata():
    metadata = get_agent_runtime_metadata(
        model="gemini-test-model"
    )

    assert metadata == {
        "agent_name": AGENT_NAME,
        "agent_version": AGENT_VERSION,
        "provider": "google",
        "model": "gemini-test-model",
    }


def test_runtime_metadata_rejects_empty_model():
    with pytest.raises(
        ValueError,
        match="model must not be empty",
    ):
        get_agent_runtime_metadata(
            model=""
        )


def test_runtime_metadata_rejects_whitespace_model():
    with pytest.raises(
        ValueError,
        match="model must not be empty",
    ):
        get_agent_runtime_metadata(
            model="   "
        )


def test_adk_finding_schema_creation():
    finding = ADKAgentFinding(
        category="URL",
        finding="Credential-related URL path detected",
        severity="HIGH",
        confidence=0.92,
        evidence_refs=[
            "security.url.credential_path_keyword"
        ],
    )

    assert finding.category == "URL"
    assert finding.severity == "HIGH"
    assert finding.confidence == 0.92

    assert finding.evidence_refs == [
        "security.url.credential_path_keyword"
    ]


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_adk_finding_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValidationError
    ):
        ADKAgentFinding(
            category="URL",
            finding="Finding",
            severity="HIGH",
            confidence=confidence,
        )


def test_adk_recommendation_schema_creation():
    recommendation = ADKAgentRecommendation(
        disposition="QUARANTINE",
        confidence=0.95,
        reasons=[
            "Multiple independent indicators detected"
        ],
        requires_human_review=False,
    )

    assert (
        recommendation.disposition
        == "QUARANTINE"
    )

    assert recommendation.confidence == 0.95

    assert (
        recommendation.requires_human_review
        is False
    )


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_adk_recommendation_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValidationError
    ):
        ADKAgentRecommendation(
            disposition="MONITOR",
            confidence=confidence,
            reasons=[
                "Observation required"
            ],
        )


def test_adk_model_metadata_schema():
    metadata = ADKAgentModelMetadata(
        provider="google",
        model_name="gemini-test-model",
        agent_version="0.1.0",
        request_id="request-001",
    )

    assert metadata.provider == "google"

    assert (
        metadata.model_name
        == "gemini-test-model"
    )

    assert (
        metadata.agent_version
        == "0.1.0"
    )

    assert (
        metadata.request_id
        == "request-001"
    )


def test_adk_review_result_schema():
    result = ADKAgentReviewResult(
        message_id="msg-001",

        findings=[
            ADKAgentFinding(
                category="URL",
                finding=(
                    "Credential-related URL "
                    "path detected"
                ),
                severity="HIGH",
                confidence=0.90,
                evidence_refs=[
                    (
                        "security.url."
                        "credential_path_keyword"
                    )
                ],
            )
        ],

        recommendation=(
            ADKAgentRecommendation(
                disposition="QUARANTINE",
                confidence=0.94,
                reasons=[
                    (
                        "URL and sender evidence "
                        "support containment"
                    )
                ],
                requires_human_review=False,
            )
        ),

        explanation=(
            "The message contains multiple "
            "independent suspicious indicators."
        ),

        model_metadata=(
            ADKAgentModelMetadata(
                provider="google",
                model_name="gemini-test-model",
                agent_version="0.1.0",
            )
        ),
    )

    assert (
        result.message_id
        == "msg-001"
    )

    assert len(
        result.findings
    ) == 1

    assert (
        result.recommendation.disposition
        == "QUARANTINE"
    )


def test_adk_review_result_serializes_to_json():
    result = ADKAgentReviewResult(
        message_id="msg-json",

        findings=[],

        recommendation=(
            ADKAgentRecommendation(
                disposition="ALLOW",
                confidence=0.85,
                reasons=[
                    "No material suspicious evidence"
                ],
            )
        ),

        explanation=(
            "No significant threat indicators "
            "were identified."
        ),

        model_metadata=(
            ADKAgentModelMetadata(
                provider="google",
                model_name="gemini-test-model",
                agent_version="0.1.0",
            )
        ),
    )

    serialized = result.model_dump_json()

    assert isinstance(
        serialized,
        str,
    )

    assert (
        '"message_id":"msg-json"'
        in serialized
    )


def test_adk_review_result_json_schema_generation():
    schema = (
        ADKAgentReviewResult
        .model_json_schema()
    )

    assert isinstance(
        schema,
        dict,
    )

    assert (
        "properties"
        in schema
    )

    assert (
        "message_id"
        in schema["properties"]
    )

    assert (
        "recommendation"
        in schema["properties"]
    )


def test_tool_functions_available_for_adk():
    functions = (
        get_message_review_tool_functions()
    )

    assert len(
        functions
    ) == 4

    assert all(
        callable(
            function
        )
        for function in functions
    )


def test_expected_tool_function_names():
    functions = (
        get_message_review_tool_functions()
    )

    names = {
        function.__name__
        for function in functions
    }

    assert names == {
        "inspect_url_evidence_dict",
        "inspect_sender_evidence_dict",
        "inspect_language_evidence_dict",
        "lookup_threat_intelligence_for_agent",
    }


def test_instruction_available_for_runtime():
    assert MESSAGE_REVIEW_INSTRUCTION

    assert (
        "UNTRUSTED EVIDENCE"
        in MESSAGE_REVIEW_INSTRUCTION
    )

    assert (
        "OUTPUT REQUIREMENTS"
        in MESSAGE_REVIEW_INSTRUCTION
    )

    assert (
        "FINDING CATEGORY CONSTRAINT"
        in MESSAGE_REVIEW_INSTRUCTION
    )

    assert (
        "MODEL_CONFLICT"
        in MESSAGE_REVIEW_INSTRUCTION
    )

    assert (
        "Do not invent new category names"
        in MESSAGE_REVIEW_INSTRUCTION
    )


def test_agent_name_is_valid_for_runtime():
    assert AGENT_NAME
    assert (
        AGENT_NAME
        == "message_review_agent"
    )


def test_agent_version_is_available_for_metadata():
    assert AGENT_VERSION == "0.1.0"


def test_create_agent_rejects_empty_model_before_adk_import():
    with pytest.raises(
        ValueError,
        match="model must not be empty",
    ):
        create_message_review_agent(
            model=""
        )


def test_create_agent_rejects_whitespace_model():
    with pytest.raises(
        ValueError,
        match="model must not be empty",
    ):
        create_message_review_agent(
            model="   "
        )


def test_create_agent_without_adk_returns_clear_runtime_error(
    monkeypatch,
):
    """
    Simulate an environment where google-adk is unavailable.

    The factory must fail cleanly without affecting the rest
    of the project.
    """

    import builtins

    real_import = builtins.__import__

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name.startswith(
            "google.adk"
        ):
            raise ImportError(
                "simulated missing google-adk"
            )

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "google-adk is not installed"
        ),
    ):
        create_message_review_agent(
            model="gemini-test-model"
        )


def test_agent_factory_configuration_with_mock_adk(
    monkeypatch,
):
    """
    Test agent construction without importing the real ADK package
    or making a model/network call.
    """

    captured = {}

    class FakeAgent:
        def __init__(
            self,
            **kwargs,
        ):
            captured.update(
                kwargs
            )

    import builtins

    real_import = builtins.__import__

    class FakeAgentsModule:
        Agent = FakeAgent

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name == "google.adk.agents":
            return FakeAgentsModule()

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    agent = create_message_review_agent(
        model="gemini-test-model"
    )

    assert isinstance(
        agent,
        FakeAgent,
    )

    assert (
        captured["name"]
        == AGENT_NAME
    )

    assert (
        captured["model"]
        == "gemini-test-model"
    )

    assert (
        captured["instruction"]
        == MESSAGE_REVIEW_INSTRUCTION
    )

    assert (
        captured["output_schema"]
        is ADKAgentReviewResult
    )

    assert (
        captured["output_key"]
        == "message_review_result"
    )


def test_agent_factory_registers_four_tools(
    monkeypatch,
):
    captured = {}

    class FakeAgent:
        def __init__(
            self,
            **kwargs,
        ):
            captured.update(
                kwargs
            )

    import builtins

    real_import = builtins.__import__

    class FakeAgentsModule:
        Agent = FakeAgent

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name == "google.adk.agents":
            return FakeAgentsModule()

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    create_message_review_agent(
        model="gemini-test-model"
    )

    tools = captured[
        "tools"
    ]

    assert len(
        tools
    ) == 4

    assert all(
        callable(
            tool
        )
        for tool in tools
    )


def test_agent_factory_description_is_present(
    monkeypatch,
):
    captured = {}

    class FakeAgent:
        def __init__(
            self,
            **kwargs,
        ):
            captured.update(
                kwargs
            )

    import builtins

    real_import = builtins.__import__

    class FakeAgentsModule:
        Agent = FakeAgent

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name == "google.adk.agents":
            return FakeAgentsModule()

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    create_message_review_agent(
        model="gemini-test-model"
    )

    assert (
        captured["description"]
    )

    assert (
        "enterprise email-security"
        in captured["description"]
    )


def test_agent_factory_does_not_execute_tools(
    monkeypatch,
):
    """
    Agent construction should only register tools.

    It must not execute any tool during factory creation.
    """

    calls = []

    def fake_tool(
        *args,
        **kwargs,
    ):
        calls.append(
            (
                args,
                kwargs,
            )
        )

        return {}

    monkeypatch.setattr(
        (
            "threat_triage.agents."
            "message_review_agent."
            "get_message_review_tool_functions"
        ),
        lambda: [
            fake_tool
        ],
    )

    captured = {}

    class FakeAgent:
        def __init__(
            self,
            **kwargs,
        ):
            captured.update(
                kwargs
            )

    import builtins

    real_import = builtins.__import__

    class FakeAgentsModule:
        Agent = FakeAgent

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name == "google.adk.agents":
            return FakeAgentsModule()

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    create_message_review_agent(
        model="gemini-test-model"
    )

    assert calls == []


def test_agent_factory_does_not_make_network_call(
    monkeypatch,
):
    """
    Factory construction must remain local.

    No model invocation should happen until a runner/runtime
    explicitly executes the agent.
    """

    class FakeAgent:
        def __init__(
            self,
            **kwargs,
        ):
            self.kwargs = kwargs

    import builtins

    real_import = builtins.__import__

    class FakeAgentsModule:
        Agent = FakeAgent

    def fake_import(
        name,
        globals=None,
        locals=None,
        fromlist=(),
        level=0,
    ):
        if name == "google.adk.agents":
            return FakeAgentsModule()

        return real_import(
            name,
            globals,
            locals,
            fromlist,
            level,
        )

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    agent = create_message_review_agent(
        model="gemini-test-model"
    )

    assert isinstance(
        agent,
        FakeAgent,
    )


def test_structured_output_contract_contains_required_fields():
    schema = (
        ADKAgentReviewResult
        .model_json_schema()
    )

    required = set(
        schema["required"]
    )

    assert required == {
        "message_id",
        "findings",
        "recommendation",
        "explanation",
    }


def test_structured_output_contract_excludes_runtime_metadata():
    schema = (
        ADKAgentReviewResult
        .model_json_schema()
    )

    assert (
        "model_metadata"
        not in schema["properties"]
    )


def test_finding_schema_contains_evidence_refs():
    schema = (
        ADKAgentFinding
        .model_json_schema()
    )

    assert (
        "evidence_refs"
        in schema["properties"]
    )


def test_recommendation_schema_contains_human_review_flag():
    schema = (
        ADKAgentRecommendation
        .model_json_schema()
    )

    assert (
        "requires_human_review"
        in schema["properties"]
    )


def test_adk_finding_rejects_unknown_category():
    with pytest.raises(ValidationError):
        ADKAgentFinding(
            category="ML_EVALUATION",
            finding="Model analysis",
            severity="HIGH",
            confidence=0.90,
        )


def test_adk_finding_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        ADKAgentFinding(
            category="MODEL_CONFLICT",
            finding="Model analysis",
            severity="VERY_HIGH",
            confidence=0.90,
        )


def test_adk_recommendation_rejects_unknown_disposition():
    with pytest.raises(ValidationError):
        ADKAgentRecommendation(
            disposition="BLOCK_FOREVER",
            confidence=0.90,
            reasons=[
                "Unsupported disposition"
            ],
        )


def test_adk_finding_schema_exposes_category_enum():
    schema = ADKAgentFinding.model_json_schema()

    category_schema = (
        schema["properties"]["category"]
    )

    assert (
        "$ref" in category_schema
        or "enum" in category_schema
    )


def test_instruction_constrains_finding_categories():
    expected_categories = {
        "URL",
        "SENDER",
        "LANGUAGE",
        "THREAT_INTELLIGENCE",
        "MESSAGE_CONTEXT",
        "MODEL_CONFLICT",
        "POLICY",
    }

    for category in expected_categories:
        assert (
            category
            in MESSAGE_REVIEW_INSTRUCTION
        )

   
def test_instruction_forbids_custom_category_names():
    assert (
        "Do not invent new category names"
        in MESSAGE_REVIEW_INSTRUCTION
    )