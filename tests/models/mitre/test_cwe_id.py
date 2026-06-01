"""tests/models/mitre/test_cwe_id.py - unit tests for the CweId primitive."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models import CweId
from models.mitre.cwe_id import _validate_cwe_id

pytestmark = pytest.mark.unit


class _CweIdProbe(BaseModel):
    """Thin probe model to drive the CweId validator in isolation."""

    value: CweId


class TestCweId:
    @pytest.mark.parametrize("raw", [1, 79, 89, 611, 99999])
    def test_accepts_shape_valid_ids(self, raw):
        # Shape-only: a high but in-range id we have not vendored is still
        # valid - CweId checks shape, not local-catalogue membership.
        assert _CweIdProbe(value=raw).value == raw

    @pytest.mark.parametrize("bad", [0, -1, -89, 100_001])
    def test_rejects_out_of_range(self, bad):
        with pytest.raises(ValidationError):
            _CweIdProbe(value=bad)

    @pytest.mark.parametrize("bad", [True, 7.5, "89"])
    def test_validator_rejects_non_int(self, bad):
        # The type guard fires on non-ints (bool is an int subclass; a float or
        # str must not slip through). Tested by calling the validator directly:
        # Pydantic's lax model path would coerce these before the AfterValidator
        # runs, so the guard's own branch is only reachable here.
        with pytest.raises(ValueError):
            _validate_cwe_id(bad)

    def test_runtime_type_is_int(self):
        probe = _CweIdProbe(value=89)
        assert isinstance(probe.value, int)
        assert f"CWE-{probe.value}" == "CWE-89"
