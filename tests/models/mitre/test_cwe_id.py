"""tests/models/mitre/test_cwe_id.py - unit tests for the CweId primitive."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models import CweId

pytestmark = pytest.mark.unit


class _CweIdProbe(BaseModel):
    """Thin probe model to drive the CweId validator in isolation."""

    value: CweId


class _StrictCweIdProbe(BaseModel):
    """Strict-mode probe: Pydantic does not int-coerce, so the validator's
    own type guard is reachable (the lax path coerces ``True`` -> ``1`` before
    the AfterValidator runs)."""

    model_config = {"strict": True}

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

    def test_rejects_bool_on_strict_path(self):
        # bool is an int subclass; a True/False slipping in as a CWE id is a
        # bug. The lax model path coerces True->1 before the AfterValidator
        # runs, so the guard is exercised via the strict path where it fires.
        with pytest.raises(ValidationError):
            _StrictCweIdProbe(value=True)

    def test_runtime_type_is_int(self):
        probe = _CweIdProbe(value=89)
        assert isinstance(probe.value, int)
        assert f"CWE-{probe.value}" == "CWE-89"
