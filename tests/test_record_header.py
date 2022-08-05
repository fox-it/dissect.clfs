# Local imports
from dissect.clfs.c_clfs import c_clfs, BlockHeader


def test_record_header_c_definitions(control_record_blf):
    r_header = c_clfs.CLFS_LOG_BLOCK_HEADER(control_record_blf)

    assert r_header.MajorVersion == 0x15
    assert r_header.MinorVersion == 0x0
    assert r_header.Fixup == 0x1
    assert r_header.ClientId == 0x0
    assert r_header.TotalSectors == 0x2
    assert r_header.ValidSectors == 0x2
    assert r_header.Reserved1 == 0x0
    assert r_header.Checksum == 0xC64C824B
    assert r_header.Flags == 0x1
    assert r_header.Reserved2 == 0x0
    assert r_header.CurrentLsn.PhysicalOffset == 0xFFFFFFFF00000000
    assert r_header.NextLsn.PhysicalOffset == 0xFFFFFFFF00000000
    assert r_header.RecordOffsets[0] == 0x70
    assert r_header.FixupOffset == 0x3F8


def test_record_header(control_record_blf):
    logblock = BlockHeader(fh=control_record_blf, offset=0)

    assert logblock.header.MajorVersion == 0x15
    assert logblock.header.MinorVersion == 0x0
    assert logblock.header.Fixup == 0x1
    assert logblock.header.ClientId == 0x0
    assert logblock.header.TotalSectors == 0x2
    assert logblock.header.ValidSectors == 0x2
    assert logblock.header.Reserved1 == 0x0
    assert logblock.header.Checksum == 0xC64C824B
    assert logblock.header.Flags == 0x1
    assert logblock.header.Reserved2 == 0x0
    assert logblock.header.CurrentLsn.PhysicalOffset == 0xFFFFFFFF00000000
    assert logblock.header.NextLsn.PhysicalOffset == 0xFFFFFFFF00000000
    assert logblock.header.RecordOffsets[0] == 0x70
    assert logblock.header.FixupOffset == 0x3F8
