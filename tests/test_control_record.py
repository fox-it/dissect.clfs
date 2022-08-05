import pytest

# Local imports
from dissect.clfs.c_clfs import c_clfs
from dissect.clfs.blf import BLF
from dissect.clfs.exceptions import InvalidRecordBlockError


def test_control_record_c_definitions(control_record_blf):
    # Seek to start of the control record
    control_record_blf.seek(0x70)

    c_record = c_clfs.CLFS_CONTROL_RECORD(control_record_blf)

    assert c_record.RecordHeader.DumpCount == 0x1
    assert c_record.Magic == 0xC1F5C1F500005F1C
    assert c_record.Version == 0x1
    assert c_record.Reserved1 == 0x0
    assert c_record.Reserved2 == 0x0
    assert c_record.Reserved3 == 0x0
    assert c_record.ExtendState == 0x0
    assert c_record.ExtendBlock == 0x0
    assert c_record.FlushBlock == 0x0
    assert c_record.NewBlockSectors == 0x0
    assert c_record.ExtendStartSectors == 0x0
    assert c_record.ExtendSectors == 0x0
    assert c_record.Blocks == 0x6


def test_control_record_blf(control_record_blf):

    blf = BLF(fh=control_record_blf)

    assert blf.c_record.record.RecordHeader.DumpCount == 0x1
    assert blf.c_record.record.Magic == 0xC1F5C1F500005F1C
    assert blf.c_record.record.Version == 0x1
    assert blf.c_record.record.Reserved1 == 0x0
    assert blf.c_record.record.Reserved2 == 0x0
    assert blf.c_record.record.Reserved3 == 0x0
    assert blf.c_record.record.ExtendState == 0x0
    assert blf.c_record.record.ExtendBlock == 0x0
    assert blf.c_record.record.FlushBlock == 0x0
    assert blf.c_record.record.NewBlockSectors == 0x0
    assert blf.c_record.record.ExtendStartSectors == 0x0
    assert blf.c_record.record.ExtendSectors == 0x0
    assert blf.c_record.record.Blocks == 0x6


def test_control_record_fail(bad_control_record_blf):

    with pytest.raises(InvalidRecordBlockError):
        BLF(fh=bad_control_record_blf)
