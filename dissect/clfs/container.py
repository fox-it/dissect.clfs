from typing import BinaryIO, Iterator, Tuple

# Local import
from dissect.clfs.c_clfs import BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidRecordBlockError


class Container:
    """Main class for parsing the containers that belong to a BLF file parsed in an earlier stage.

    Args:
        fh: A file handle to a container file.
        offset: The offset to start parsing the container records.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset

    def _open_block(self, offset: int) -> Tuple[BinaryIO, int]:
        """Open the blockheader of every block that is present within the given container.

        Returns:
            buf, cur_record_offset: Tuple containing a file-like object of the log block and the current offset.
        """

        try:
            log_block = BlockHeader(fh=self.fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid container block header, possibly corrupt/empty")

        cur_record_offset = log_block.header.RecordOffsets[0]

        buf = log_block.open()
        buf.seek(cur_record_offset)

        return buf, cur_record_offset

    def records(self) -> Iterator[Tuple[int, bytes, bytes]]:
        """Parse the records that are present within the log block."""

        log_block_offset = self.offset

        buf, cur_record_offset = self._open_block(log_block_offset)
        cur_record_header = c_clfs.RECORD_HEADER(buf)

        while True:
            # Data block
            if cur_record_header.Type & c_clfs.RecordType.ClfsDataRecord:
                cur_block_data = buf.read(cur_record_header.DataSize - cur_record_header.Offset)

            # Start of record header
            if cur_record_header.Type & c_clfs.RecordType.ClfsStartRecord:
                """
                This may seem odd to do, but the actual data offset is present in the start record for the record block.

                The record data is placed right after the header itself, meaning that if you read the entire block, you
                can subtract the offset (size of header) from the data size itself and be left with the record data.
                """

                # Advance to the next RECORD_HEADER
                next_record_header = c_clfs.RECORD_HEADER(buf)

                # The record data is present right after the record header, subtract the header size (offset field)
                # from the data size
                cur_record_data = buf.read(next_record_header.DataSize - next_record_header.Offset)

                yield log_block_offset + cur_record_offset, cur_record_data, cur_block_data

                # End of log sequence
                if next_record_header.LsnPrevious == 0:
                    break

                # Set the new block offset
                log_block_offset = next_record_header.LsnPrevious - 1
                cur_record_header = next_record_header
                continue

            # End of block, pointer to new block
            if cur_record_header.Type & c_clfs.RecordType.ClfsLastRecord:
                buf, cur_record_offset = self._open_block(log_block_offset)
                cur_record_header = c_clfs.RECORD_HEADER(buf)
