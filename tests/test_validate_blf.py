from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.clfs.blf import BLF
from dissect.clfs.exceptions import InvalidBLFError


def test_validate(control_record_blf: BinaryIO) -> None:
    BLF(fh=control_record_blf)


def test_validate_fail(invalid_control_record_blf: BinaryIO) -> None:
    with pytest.raises(InvalidBLFError):
        BLF(fh=invalid_control_record_blf)
