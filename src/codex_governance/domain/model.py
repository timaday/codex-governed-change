"""Stable domain vocabulary for the implementation tasks."""

from enum import StrEnum


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ReviewerVerdict(StrEnum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class DispositionState(StrEnum):
    READY_FOR_HUMAN = "READY_FOR_HUMAN"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class ClaimClassification(StrEnum):
    PROVEN = "PROVEN"
    SUPPORTED = "SUPPORTED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"
