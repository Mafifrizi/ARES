"""Public ARES SDK parameter schema models and helpers.

Provides Pydantic v2 typed parameter definitions for module authors:
    from ares.sdk import ModuleParams, param, SecretParam
"""
from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, Field, SecretStr, ValidationError

from ares.core.errors import ModuleValidationError
from ares.modules.params import ModuleParams, SecretParam, param

P = TypeVar("P", bound=BaseModel)


def validate_params(
    model_cls: type[P],
    data: dict[str, Any] | BaseModel | None,
    module_id: str = "",
) -> P:
    """Validate a parameter dictionary or model against a Pydantic model.

    Raises ModuleValidationError with structured field-level errors on failure.
    """
    if data is None:
        data = {}
    if isinstance(data, model_cls):
        return data
    if isinstance(data, BaseModel):
        data = data.model_dump()

    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        first_error = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(x) for x in first_error.get("loc", []))
        msg = first_error.get("msg", "Invalid parameters")
        detail = f"Parameter validation failed for {loc}: {msg}" if loc else f"Parameter validation failed: {msg}"
        raise ModuleValidationError(
            detail,
            module_id=module_id,
            field=loc or "params",
        ) from exc


__all__ = [
    "ModuleParams",
    "param",
    "SecretParam",
    "SecretStr",
    "Field",
    "BaseModel",
    "validate_params",
]
