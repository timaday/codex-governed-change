"""Task-contract quality-profile validation skeleton."""

from collections.abc import Mapping
from typing import Any


def validate_task_contract(contract: Mapping[str, Any]) -> list[str]:
    """Return deterministic requirement violations for the selected profile."""
    del contract
    raise NotImplementedError("T07: implement task profile validation")
