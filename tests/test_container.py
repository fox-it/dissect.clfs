from collections import namedtuple

# Local imports
from dissect.clfs.container import Container


Data = namedtuple("Data", ["offset", "r_data", "b_data"])


def test_container_records(dummy_container):
    records = []

    trans = Container(fh=dummy_container, offset=36864)

    for r_offset, r_data, b_data in trans.records():
        records.append(Data(offset=r_offset, r_data=r_data, b_data=b_data))

    assert len(records) == 12

    assert records[0].offset == 36976

    expected_first_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    assert records[0].r_data == expected_first_record_data

    expected_first_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        be 8e 6b c1 61 db ec 11
        a4 ba 00 50 56 ef c5 14
        0d 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    assert records[0].b_data == expected_first_block_data

    expected_last_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    assert records[-1].r_data == expected_last_record_data

    expected_last_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        e1 b9 29 a6 ea d7 eb 11
        a4 6b 3c 22 fb 13 6b f1
        21 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    assert records[-1].b_data == expected_last_block_data
