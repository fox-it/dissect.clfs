import pytest

# Local imports
from dissect.clfs.blf import BLF
from dissect.clfs.exceptions import InvalidBLFError


def test_validate(control_record_blf):
    BLF(fh=control_record_blf)


def test_validate_fail(invalid_control_record_blf):
    with pytest.raises(InvalidBLFError):
        BLF(fh=invalid_control_record_blf)
