import io
from typing import BinaryIO

# External dependencies
from dissect.cstruct import cstruct


clfs_def = """
/* ======== Generic Windows ======== */
flag FILE_ATTRIBUTES : USHORT {
    READONLY                    = 0x00000001,
    HIDDEN                      = 0x00000002,
    SYSTEM                      = 0x00000004,
    DIRECTORY                   = 0x00000010,
    ARCHIVE                     = 0x00000020,
    DEVICE                      = 0x00000040,
    NORMAL                      = 0x00000080,
    TEMPORARY                   = 0x00000100,
    SPARSE_FILE                 = 0x00000200,
    REPARSE_POINT               = 0x00000400,
    COMPRESSED                  = 0x00000800,
    OFFLINE                     = 0x00001000,
    NOT_CONTENT_INDEXED         = 0x00002000,
    ENCRYPTED                   = 0x00004000,
    VIRTUAL                     = 0x00010000,
    INVALID_FILE_ATTRIBUTES     = 0xFFFFFFFF,
};

typedef UCHAR CLFS_CLIENT_ID;

typedef DWORD CLFS_RECORD_INDEX;
typedef DWORD CLFS_CONTAINER_ID;

// Taken from clfslsn.h (Windows SDK)
typedef union CLFS_LSN {
    struct {
        CLFS_RECORD_INDEX   RecordIndex;
        CLFS_CONTAINER_ID   ContainerId;
    } Offset;

    ULONGLONG PhysicalOffset;
};

typedef enum CLFS_NODE_TYPE : DWORD {
    FCB                      = 0xC1FDF001,
    VCB                      = 0xC1FDF002,
    CCB                      = 0xC1FDF003,
    REQ                      = 0xC1FDF004,
    CCA                      = 0xC1FDF005,
    SYMBOL                   = 0xC1FDF006,
    CLIENT_CONTEXT           = 0xC1FDF007,
    CONTAINER_CONTEXT        = 0xC1FDF008,
    SHARED_SECURITY_CONTEXT  = 0xC1FDF00D,
    DEVICE_EXTENSION         = 0xC1FDF009,
    MARSHALING_AREA          = 0xC1FDF00A,
    ARCHIVE_CONTEXT          = 0xC1FDF00C,
    SCAN_CONTEXT             = 0xC1FDF00E,
    LOG_READ_IOCB            = 0xC1FDF00F,
    LOG_WRITE_IOCB           = 0xC1FDF010,
};

typedef struct CLFS_NODE_ID {
    CLFS_NODE_TYPE Type;
    DWORD Node;
};

/* ======== Log Block Header ======== */

typedef enum CLFS_LOG_BLOCK_FLAGS : DWORD {
    RESET             = 0x00000000,
    ENCODED           = 0x00000001,
    DECODED           = 0x00000002,
    LATCHED           = 0x00000004,
    TRUNCATE_DISCARD  = 0x00000008,
};

typedef struct CLFS_LOG_BLOCK_HEADER {
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    UCHAR Fixup;
    UCHAR ClientId;
    USHORT TotalSectors;
    USHORT ValidSectors;
    DWORD Reserved1;
    DWORD Checksum;
    CLFS_LOG_BLOCK_FLAGS Flags;
    DWORD Reserved2;
    CLFS_LSN CurrentLsn;
    CLFS_LSN NextLsn;
    DWORD RecordOffsets[16];
    DWORD FixupOffset;
};

/* ======== Control Record ======== */

typedef struct CLFS_METADATA_RECORD_HEADER {
    ULONGLONG DumpCount;
};

typedef enum CLFS_EXTEND_STATE : DWORD {
    ClfsExtendStateNone             = 0x00000000,
    ClfsExtendStateExtendingFsd     = 0x00000001,
    ClfsExtendStateFlushingBlock    = 0x00000002,
};

typedef enum CLFS_TRUNCATE_STATE : DWORD {
    ClfsTruncateStateNone                   = 0x00000000,
    ClfsTruncateStateModifyingStream        = 0x00000001,
    ClfsTruncateStateSavingOwner            = 0x00000002,
    ClfsTruncateStateModifyingOwner         = 0x00000003,
    ClfsTruncateStateSavingDiscardBlock     = 0x00000004,
    ClfsTruncateStateModifyingDiscardBlock  = 0x00000005,
};

typedef struct CLFS_TRUNCATE_CONTEXT {
    CLFS_TRUNCATE_STATE TruncateState;
    UCHAR Clients;
    UCHAR Client;
    USHORT TruncateField;
    CLFS_LSN LsnOwnerPage;
    CLFS_LSN LsnLastOwnerPage;
    ULONGLONG InvalidSector;
};

typedef enum CLFS_METADATA_BLOCK_TYPE : DWORD {
    ClfsMetaBlockControl          = 0x00000000,
    ClfsMetaBlockControlShadow    = 0x00000001,
    ClfsMetaBlockGeneral          = 0x00000002,
    ClfsMetaBlockGeneralShadow    = 0x00000003,
    ClfsMetaBlockScratch          = 0x00000004,
    ClfsMetaBlockScratchShadow    = 0x00000005,
};

typedef struct CLFS_METADATA_BLOCK {
    union {
        ULONGLONG Image;
        ULONGLONG Alignment;
    };

    DWORD Image;
    DWORD Offset;
    CLFS_METADATA_BLOCK_TYPE Type;
    DWORD Padding;
};

typedef struct CLFS_CONTROL_RECORD {
    CLFS_METADATA_RECORD_HEADER RecordHeader;
    ULONGLONG Magic;
    UCHAR Version;
    UCHAR Reserved1;
    UCHAR Reserved2;
    UCHAR Reserved3;
    CLFS_EXTEND_STATE ExtendState;
    USHORT ExtendBlock;
    USHORT FlushBlock;
    DWORD NewBlockSectors;
    DWORD ExtendStartSectors;
    DWORD ExtendSectors;
    CLFS_TRUNCATE_CONTEXT Truncate;
    DWORD Blocks;
    DWORD Reserved4 ;
    CLFS_METADATA_BLOCK RgBlocks[Blocks];
};

/* ======== Base Record ======== */

typedef struct CLFS_BASE_RECORD_HEADER {
    CLFS_METADATA_RECORD_HEADER RecordHeader;
    UCHAR IdLog[16];
    ULONGLONG ClientSymbolTable[11];
    ULONGLONG ContainerSymbolTable[11];
    ULONGLONG SecuritySymbolTable[11];
    DWORD NextContainer;
    DWORD NextClient;
    DWORD FreeContainers;
    DWORD ActiveContainers;
    DWORD FreeContainersCount;
    DWORD BusyContainers;
    DWORD ClientContainers[124];
    DWORD ContainerArray[1024];
    DWORD SymbolZone;
    DWORD Sector;
    UCHAR Unused1;
    UCHAR Unused2;
    UCHAR Unused3;
    UCHAR Usn;
    UCHAR Clients;
};

typedef struct CLFS_HASH_SYM {
    CLFS_NODE_ID NodeId;
    DWORD UlHash;
    DWORD CbHash;
    ULONGLONG Below;
    ULONGLONG Above;
    DWORD SymbolName;
    USHORT Offset;
    USHORT Deleted;
};

typedef enum CLFS_LOG_STATE : DWORD {
    UNINITIALIZED    = 0x00000001,
    INITIALIZED      = 0x00000002,
    ACTIVE           = 0x00000004,
    PENDING_DELETE   = 0x00000008,
    PENDING_ARCHIVE  = 0x00000010,
    SHUTDOWN         = 0x00000020,
    MULTIPLEXED      = 0x00000040,
    SECURE           = 0x00000080,
};

typedef struct CLFS_CLIENT_CONTEXT {
    CLFS_NODE_ID NodeId;
    CLFS_CLIENT_ID ClientId;
    UCHAR Unknown1;
    FILE_ATTRIBUTES FileAttributes;
    DWORD FlushThreshold;
    ULONGLONG Unknown2[5]; // could be timestamp?
    CLFS_LSN LsnArchiveTail;
    CLFS_LSN LsnBase;
    CLFS_LSN LsnFlush;
    CLFS_LSN LsnLast;
    CLFS_LSN LsnPhysicalBase;
    CLFS_LSN LsnUnused1;
    CLFS_LSN LsnUnused2;
    CLFS_LOG_STATE State;
    ULONGLONG SecurityContext;
};

typedef struct CLFS_CONTAINER_CONTEXT {
    CLFS_NODE_ID NodeId;
    ULONGLONG Container;
    CLFS_CONTAINER_ID ContainerId;
    CLFS_CONTAINER_ID QueueId;
    ULONGLONG Alignment;
    UCHAR CurrentUsn;
    UCHAR State;
    DWORD PreviousOffset;
    DWORD NextOffset;
};

// This should only ever be present in-memory
typedef struct CLFS_SHARED_SECURITY_CONTEXT {
    CLFS_NODE_ID NodeId;
    DWORD Ref;
    DWORD RefActive;
    DWORD DescriptorOffset;
    DWORD Descriptor;
    UCHAR RgSecurityDescriptor[0]; // initialize as 0 for now, we're only parsing persistent files
};

/* ======== Truncate Record ======== */

typedef struct CLFS_TRUNCATE_RECORD_HEADER {
    CLFS_METADATA_RECORD_HEADER RecordHeader;
    DWORD ClientChangeOffset;
    DWORD OwnerPageOffset;
};

typedef struct CLFS_SECTOR_CHANGE {
    DWORD InitializedSector;
    DWORD Unused;
    UCHAR Sector[512];    // CLFS sector size
};

typedef struct CLFS_TRUNCATE_CLIENT_CHANGE {
    CLFS_CLIENT_ID ClientId;
    CLFS_LSN Lsn;
    CLFS_LSN LsnClient;
    CLFS_LSN LsnRestart;
    USHORT Length;
    USHORT OldLength;
    DWORD Sectors;
    CLFS_SECTOR_CHANGE RgSectors[Sectors];
};

/* ======== Container Record Header ======== */

flag RecordType : DWORD {
    ClfsNullRecord          = 0x00000000, // Null record
    ClfsDataRecord          = 0x00000001, // The log record contains client data
    ClfsRestartRecord       = 0x00000002, // The log record is a restart record
    ClfsStartRecord         = 0x00000004, // Start of continuation record
    ClfsEndRecord           = 0x00000008, // End of continuation record
    ClfsContinuationRecord  = 0x00000010, // Continuation record
    ClfsLastRecord          = 0x00000020, // The last record in the log block
};

typedef struct RECORD_HEADER {
    ULONGLONG LsnVirtual;
    ULONGLONG LsnUndoNext;
    ULONGLONG LsnPrevious;
    DWORD DataSize;
    DWORD Unknown;
    USHORT RecordFlags;
    USHORT Offset;
    RecordType Type;
};
"""

c_clfs = cstruct()
c_clfs.load(clfs_def)

SECTOR_SIZE = 512
CLFS_CONTROL_RECORD_MAGIC_VALUE = 0xC1F5C1F500005F1C


class BlockHeader:
    """Main class to parse the block headers.

    Args:
        fh: A file-like object.
        offset: Offset to start reading the block header from.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.offset = offset

        fh.seek(self.offset)
        self.header = c_clfs.CLFS_LOG_BLOCK_HEADER(fh)

        fh.seek(self.offset)
        data = bytearray(fh.read(self.header.TotalSectors * SECTOR_SIZE))
        view = memoryview(data)

        fixup = view[self.header.FixupOffset :]
        ptr = view[SECTOR_SIZE - 2 :]

        for _ in range(self.header.TotalSectors):
            ptr[:2] = fixup[:2]
            fixup = fixup[2:]
            ptr = ptr[SECTOR_SIZE:]

        self.data = bytes(data)

    def open(self):
        """Return a file-like object of the block header."""

        return io.BytesIO(self.data)
