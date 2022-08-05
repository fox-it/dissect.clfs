from collections import namedtuple
from typing import BinaryIO, Iterator

from dissect.clfs.c_clfs import CLFS_CONTROL_RECORD_MAGIC_VALUE, BlockHeader, c_clfs
from dissect.clfs.exceptions import (
    InvalidBLFError,
    InvalidContextError,
    InvalidRecordBlockError,
)

Context = namedtuple("Context", ["symbol_table", "type"])
Container = namedtuple("Container", ["name", "size", "id", "type"])
Stream = namedtuple(
    "Stream",
    [
        "name",
        "id",
        "file_attributes",
        "type",
        "lsn_archive_tail",
        "lsn_base",
        "lsn_last",
        "lsn_flush",
        "lsn_physical_base",
        "offset",
    ],
)


class ControlRecord:
    """Read the Control Record of the BLF.

    The control record is used to specify where the other blocks that make up the BLF are being stored within the
    given file. Each entry will have their image size, as well as the offset which is relative to the beginning of
    the file. This header also contains the CLFS magic value which in turn can be used to validate the given file
    (0xC1F5C1F500005F1C).

    There are 3 different types of blocks:

    - Control Block
    - General Block
    - Metadata Block

    Each of the 3 different blocks has another shadow block accompanied that is storing the information from the
    previous transaction on this block. A shadow block can be identified by the odd number in the block_type field.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the control records.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid control record block header, possibly corrupt/empty")

        record_offest = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offest)

        try:
            self.record = c_clfs.CLFS_CONTROL_RECORD(logblock_fh)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid control record, possibly corrupt/empty")

    @property
    def valid(self) -> bool:
        """Return if the control record magic is valid."""
        return self.record.Magic == CLFS_CONTROL_RECORD_MAGIC_VALUE


class BaseRecord:
    """Function to parse the base record block.

    The base record block contains information about the different containers and which clients (streams) are using
    these. The first entries in the client and container symbol tables are the ones used, the full array can have
    more than just those values, but at the time of writing it is unclear if these are artefacts from earlier
    transactions in the log.

    For every context (client, container, security) the symbol table is parsed to extract the stream and container
    data. At this point we don't do anything with the security context yet as this seems only used for in-memory
    structures of CLFS.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the base records.
        block_type: Type of CLFS block to parse.
    """

    def __init__(self, fh: BinaryIO, offset: int, block_type: int):
        self.block_type = block_type

        self.containers = []
        self.streams = []

        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid base record block header, possibly corrupt/empty")

        record_offset = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offset)

        self.record = c_clfs.CLFS_BASE_RECORD_HEADER(logblock_fh)

        # Create the 3 contexts as a named tuple for more descriptive parsing
        contexts = [
            Context(
                symbol_table=self.record.ClientSymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT,
            ),
            Context(
                symbol_table=self.record.ContainerSymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT,
            ),
            Context(
                symbol_table=self.record.SecuritySymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT,
            ),
        ]

        for ctx in contexts:
            self._symbol_table(
                sym_table=ctx.symbol_table, ctx_type=ctx.type, logblock_fh=logblock_fh, offset=record_offset
            )

    def _symbol_table(
        self, sym_table: list, ctx_type: c_clfs.CLFS_NODE_TYPE, logblock_fh: BinaryIO, offset: int
    ) -> None:
        """Function to parse the symbol tables.

        Clients, containers, and shared security contexts in the Base Log File are represented by symbols, which are
        preceded by the ClfsHashSym structure.

        The key takeaways from this structure are the symbol name which is the actualy container name the context is
        related to. This is also the name of the file on disk that is being used to write the log transaction to.

        For every stored context there is an offset noted in this structure that should be parsed seperately.

        Args:
            sym_table: The offset as denoted in the symbol table.
            ctx_type: Description of the type of context (CLIENT_CONTEXT, CONTAINER_CONTEXT, SHARED_SECURITY_CONTEXT).
            logblock_fh: A file-like object of the log block in which the symbol table resides.
            offset: Offset with start of the record.
        """
        for sym_tbl_offset in sym_table:
            if sym_tbl_offset == 0:
                continue

            # Seek towards the start of the symbol table
            logblock_fh.seek(offset + sym_tbl_offset)

            sym_tbl = c_clfs.CLFS_HASH_SYM(logblock_fh)

            if sym_tbl.NodeId.Type != c_clfs.CLFS_NODE_TYPE.SYMBOL:
                raise InvalidContextError(f"Invalid NodeId type: {sym_tbl.NodeId.Type}")

            # It looks like the size of the symbol names is not stored anywhere and
            # simply read until a null-terminator is found...
            logblock_fh.seek(offset + sym_tbl.SymbolName)
            symbol_name = b"".join(iter(lambda: logblock_fh.read(2), b"\x00\x00")).decode("utf-16")

            ctx_offset = offset + sym_tbl.Offset

            # Parse the context based on the context type
            if ctx_type == c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT:
                self.streams.append(
                    self._client_context(logblock_fh=logblock_fh, client_ctx_offset=ctx_offset, name=symbol_name)
                )

            elif ctx_type == c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT:
                self.containers.append(
                    self._container_context(logblock_fh=logblock_fh, container_ctx_offset=ctx_offset, name=symbol_name)
                )

            elif ctx_type == c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT:
                self._security_context(logblock_fh=logblock_fh, security_ctx_offset=ctx_offset)
            else:
                raise InvalidContextError(f"Invalid context type: {ctx_type}")

    def _client_context(self, logblock_fh: BinaryIO, client_ctx_offset: int, name: str) -> None:
        """Function to parse client context structures.

        The client context relates to the stream that is being used for the current transaction. The client_id
        field is used to match the container that the stream of records should be written to.

        The LSN (Logical Sequence Number) base holds the offset that is relative of the start of the container
        and points to the last transaction (actually it points to the one that is currently being transacted,
        but I'm not 100% sure about this) and is used as a starting offset when reading the container.

        NOTE: a lot more of the client context is currently being stored in the streams list, this is mostly
        because I think this might actually be valuable information for the complete dissect implementation.

        Args:
            logblock_fh: A file-like object of the log block in which the client context resides.
            client_ctx_offset: Starting offset of the client context.
            name: Filename to which the stream for the current transaction belongs to.

        Returns:
            Stream: A named tuple containing the necessary information about the client context.
        """
        logblock_fh.seek(client_ctx_offset)
        client_ctx_record = c_clfs.CLFS_CLIENT_CONTEXT(logblock_fh)

        if client_ctx_record.NodeId.Type != c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT:
            raise InvalidContextError(f"Invalid NodeId type: {client_ctx_record.NodeId.Type}")

        return Stream(
            name=name,
            id=client_ctx_record.ClientId,
            file_attributes=client_ctx_record.FileAttributes,
            type=self.block_type,
            lsn_archive_tail=client_ctx_record.LsnArchiveTail,
            lsn_base=client_ctx_record.LsnBase,
            lsn_last=client_ctx_record.LsnLast,
            lsn_flush=client_ctx_record.LsnFlush,
            lsn_physical_base=client_ctx_record.LsnPhysicalBase,
            offset=client_ctx_record.LsnPhysicalBase.Offset.RecordIndex - 1,
        )

    def _container_context(self, logblock_fh: BinaryIO, container_ctx_offset: int, name: str) -> None:
        """Function to parse container context structures.

        The container context is important to keep track of as the container ID should be in line
        with the stream ID and is thus needed to make sure that the offsets we're using are indeed
        meant for the right container if we want to parse the data correctly.

        Args:
            logblock_fh: A file-like object of the log block in which the container context resides.
            container_ctx_offset: Starting offset of the container context.
            name: Filename to which the stream for the current transaction belongs to.

        Returns:
            Container: A namedtuple containing the necessary information about the container context.
        """
        logblock_fh.seek(container_ctx_offset)
        container_ctx_record = c_clfs.CLFS_CONTAINER_CONTEXT(logblock_fh)

        if container_ctx_record.NodeId.Type != c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT:
            raise InvalidContextError(f"Invalid NodeId type: {container_ctx_record.NodeId.Type}")

        return Container(
            name=name,
            size=container_ctx_record.Container,
            id=container_ctx_record.ContainerId,
            type=self.block_type,
        )

    def _security_context(self, logblock_fh: BinaryIO, security_ctx_offset: int) -> None:
        """Function to parse the security context structures.

        NOTE: this is an in-memory structure and will be parsed at a later stage (dissect.mem bby)

        Args:
            logblock_fh: A file-like object of the log block in which the security context resides.
            security_ctx_offset: Starting offset of the security context.
        """
        logblock_fh.seek(security_ctx_offset)
        security_ctx_record = c_clfs.CLFS_SHARED_SECURITY_CONTEXT(logblock_fh)

        if security_ctx_record.NodeId.Type != c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT:
            raise InvalidContextError(f"Invalid NodeId type: {security_ctx_record.NodeId.Type}")


class TruncateRecord:
    """Parser for the truncate records within a BLF if they exist.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the truncate records.
    """

    def __init__(self, fh: BinaryIO, offset: int):

        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid truncate record block header, possibly corrupt/empty")

        record_offset = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offset)

        self.record = c_clfs.CLFS_TRUNCATE_RECORD_HEADER(logblock_fh)

        if self.record.ClientChangeOffset == 0:
            # CLFS_TRUNCATE_RECORD_HEADER = 16 bytes
            record_offset += 0x10
        else:
            record_offset += self.record.ClientChangeOffset


class BLF:
    """Main class of dissect.clfs. Parsing of BLF and information regarding the associated containers starts here.

    Args:
        fh: A file-like object to a BLF file.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.c_record = ControlRecord(fh=self.fh, offset=0)

        if not self.c_record.valid:
            raise InvalidBLFError("Invalid BLF file, possibly corrupt/empty")

        self.metablocks = self.c_record.record.RgBlocks

    def control_records(self) -> Iterator[ControlRecord]:
        """Yield the associated control records."""
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControl,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControlShadow,
            ):
                yield ControlRecord(fh=self.fh, offset=metablock.Offset)

    def base_records(self) -> Iterator[BaseRecord]:
        """Yield the associated base records.

        The base records hold most of the information regarding the parsing of the associated containers.
        """
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneralShadow,
            ):
                yield BaseRecord(fh=self.fh, offset=metablock.Offset, block_type=metablock.Type)

    def truncate_records(self) -> Iterator[TruncateRecord]:
        """Yield the truncate records.

        This has not been encountered yet.
        """
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratch,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratchShadow,
            ):
                yield TruncateRecord(fh=self.fh, offset=metablock.Offset)
