from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeAlias

from threat_triage.evaluation.models import (
    EvaluationMode,
    EvaluationPrediction,
    EvaluationResult,
    EvaluationSample,
)


EvaluationExecutor: TypeAlias = Callable[
    [EvaluationSample],
    EvaluationPrediction
    | Awaitable[EvaluationPrediction],
]


def _elapsed_ms(
    start_time_ns: int,
) -> float:
    """
    Return elapsed monotonic time in milliseconds.
    """

    elapsed_ns = (
        time.perf_counter_ns()
        - start_time_ns
    )

    return elapsed_ns / 1_000_000.0


def _build_metadata(
    sample: EvaluationSample,
) -> dict[str, object]:
    """
    Preserve evaluation metadata required by downstream metrics.

    Message content is intentionally not copied into result metadata.
    """

    metadata: dict[str, object] = {}

    if sample.threat_category is not None:
        metadata[
            "threat_category"
        ] = sample.threat_category

    if sample.source is not None:
        metadata[
            "source"
        ] = sample.source

    return metadata


def _validate_prediction(
    prediction: object,
) -> EvaluationPrediction:
    """
    Ensure injected executors respect the evaluation boundary.
    """

    if not isinstance(
        prediction,
        EvaluationPrediction,
    ):
        raise TypeError(
            "Evaluation executor must return "
            "EvaluationPrediction"
        )

    return prediction


async def _execute(
    *,
    sample: EvaluationSample,
    executor: EvaluationExecutor,
) -> EvaluationPrediction:
    """
    Execute either a synchronous or asynchronous evaluator.

    This keeps the evaluation harness independent from the underlying
    implementation. ML executors can remain synchronous while ADK/Gemini
    executors can be asynchronous.
    """

    value = executor(
        sample
    )

    if inspect.isawaitable(
        value
    ):
        value = await value

    return _validate_prediction(
        value
    )


async def evaluate_sample(
    sample: EvaluationSample,
    *,
    mode: EvaluationMode,
    executor: EvaluationExecutor,
    agent_invoked: bool | None = None,
) -> EvaluationResult:
    """
    Evaluate one sample using an injected execution strategy.

    Exceptions raised by the executor are captured as failed
    EvaluationResult records rather than escaping the evaluation loop.

    This allows large evaluation runs to continue even when an individual
    model/provider execution fails.
    """

    start_time_ns = (
        time.perf_counter_ns()
    )

    resolved_agent_invoked = (
        mode
        in {
            EvaluationMode.GEMINI_ONLY,
            EvaluationMode.HYBRID,
        }
        if agent_invoked is None
        else agent_invoked
    )

    metadata = _build_metadata(
        sample
    )

    try:
        prediction = await _execute(
            sample=sample,
            executor=executor,
        )

        return EvaluationResult(
            sample_id=sample.sample_id,
            mode=mode,
            true_label=sample.true_label,
            prediction=prediction,
            latency_ms=_elapsed_ms(
                start_time_ns
            ),
            agent_invoked=(
                resolved_agent_invoked
            ),
            metadata=metadata,
        )

    except Exception as exc:
        return EvaluationResult(
            sample_id=sample.sample_id,
            mode=mode,
            true_label=sample.true_label,
            prediction=None,
            latency_ms=_elapsed_ms(
                start_time_ns
            ),
            agent_invoked=(
                resolved_agent_invoked
            ),
            error=_format_error(
                exc
            ),
            metadata=metadata,
        )


async def evaluate_ml_sample(
    sample: EvaluationSample,
    *,
    executor: EvaluationExecutor,
) -> EvaluationResult:
    """
    Evaluate one sample using the classical ML baseline.
    """

    return await evaluate_sample(
        sample,
        mode=EvaluationMode.ML_ONLY,
        executor=executor,
        agent_invoked=False,
    )


async def evaluate_gemini_sample(
    sample: EvaluationSample,
    *,
    executor: EvaluationExecutor,
) -> EvaluationResult:
    """
    Evaluate one sample using Gemini directly.
    """

    return await evaluate_sample(
        sample,
        mode=EvaluationMode.GEMINI_ONLY,
        executor=executor,
        agent_invoked=True,
    )


async def evaluate_hybrid_sample(
    sample: EvaluationSample,
    *,
    executor: EvaluationExecutor,
    agent_invoked: bool,
) -> EvaluationResult:
    """
    Evaluate one sample using the hybrid system.

    Unlike GEMINI_ONLY, agent_invoked must be supplied by the caller because
    the hybrid path may resolve a message without invoking the agent.
    """

    return await evaluate_sample(
        sample,
        mode=EvaluationMode.HYBRID,
        executor=executor,
        agent_invoked=agent_invoked,
    )


async def evaluate_batch(
    samples: Iterable[EvaluationSample],
    *,
    mode: EvaluationMode,
    executor: EvaluationExecutor,
    agent_invoked: bool | None = None,
) -> list[EvaluationResult]:
    """
    Evaluate a collection of samples sequentially.

    Sequential execution is deliberate for the first evaluation harness:
    it gives us predictable provider behavior, easier debugging, and clean
    per-request latency measurements.

    Controlled concurrency can be added later for load evaluation.
    """

    results: list[
        EvaluationResult
    ] = []

    for sample in samples:
        result = await evaluate_sample(
            sample,
            mode=mode,
            executor=executor,
            agent_invoked=agent_invoked,
        )

        results.append(
            result
        )

    return results


def _format_error(
    exc: Exception,
) -> str:
    """
    Produce a stable error representation without serializing traceback
    information or potentially sensitive message content.
    """

    error_type = (
        type(exc).__name__
    )

    message = str(
        exc
    ).strip()

    if not message:
        return error_type

    return (
        f"{error_type}: {message}"
    )