#include <vector>
#include <iostream>

typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef char CHAR;
typedef long LONG;

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550

enum DATA_DIRECTORY_TYPE
{
    DIR_EXPORT = 0,
    DIR_IMPORT = 1,
    DIR_RESOURCE = 2,
    DIR_EXCEPTION = 3,
    DIR_SECURITY = 4,
    DIR_BASERELOC = 5,
    DIR_DEBUG = 6,
    DIR_ARCHITECTURE = 7,
    DIR_GLOBALPTR = 8,
    DIR_TLS = 9,
    DIR_LOAD_CONFIG = 10,
    DIR_BOUND_IMPORT = 11,
    DIR_IAT = 12,
    DIR_DELAY_IMPORT = 13,
    DIR_COM_DESCRIPTOR = 14,
    DIR_RESERVED = 15,
};

enum RelocType
{
    RELOC_ABSOLUTE = 0,
    RELOC_HIGH = 1,
    RELOC_LOW = 2,
    RELOC_HIGHLOW = 3,
    RELOC_HIGHADJ = 4,
    RELOC_MIPS_JMPADDR = 5,
    RELOC_MIPS_JMPADDR16 = 9,
    RELOC_IA64_IMM64 = 9,
    RELOC_DIR64 = 10
};

constexpr std::uint16_t NUM_DIR_ENTRIES = 16;
constexpr std::uint16_t NT_SHORT_NAME_LEN = 8;

struct IMAGE_DOS_HEADER
{
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::uint16_t e_res[4];
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::uint16_t e_res2[10];
    std::uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER
{
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY
{
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32
{
    std::uint16_t Magic;
    std::uint8_t MajorLinkerVersion;
    std::uint8_t MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve;
    std::uint32_t SizeOfStackCommit;
    std::uint32_t SizeOfHeapReserve;
    std::uint32_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[NUM_DIR_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64
{
    std::uint16_t Magic;
    std::uint8_t MajorLinkerVersion;
    std::uint8_t MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[NUM_DIR_ENTRIES];
};

struct IMAGE_NT_HEADERS
{
    std::uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    std::uint16_t OptionalMagic;
};

struct IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        std::uint32_t Characteristics;
        std::uint32_t OriginalFirstThunk;
    } DUMMYUNIONNAME;
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;
    std::uint32_t FirstThunk;
};

typedef unsigned long ULONG_PTR, *PULONG_PTR;
typedef long LONG_PTR, *PLONG_PTR;

struct IMAGE_THUNK_DATA
{
    union
    {
        std::uint32_t ForwarderString;
        std::uint32_t Function;
        std::uint32_t Ordinal;
        std::uint32_t AddressOfData;
    } u1;
};

struct IMAGE_IMPORT_BY_NAME
{
    std::uint16_t Hint;
    CHAR Name[ 1 ];
};

struct IMAGE_BASE_RELOCATION
{
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfBlock;
};

struct IMAGE_SECTION_HEADER
{
    BYTE Name[ NT_SHORT_NAME_LEN ];

    union
    {
        std::uint32_t PhysicalAddress;
        std::uint32_t VirtualSize;
    } Misc;

    std::uint32_t   VirtualAddress;
    std::uint32_t   SizeOfRawData;
    std::uint32_t   PointerToRawData;
    std::uint32_t   PointerToRelocations;
    std::uint32_t   PointerToLinenumbers;
    std::uint16_t   NumberOfRelocations;
    std::uint16_t   NumberOfLinenumbers;
    std::uint32_t   Characteristics;
};

#define FIELD_OFFSET( type, field )    ( ( LONG ) ( LONG_PTR ) & ( ( ( type* ) 0 )->field ) )
#define IMAGE_FIRST_SECTION( m_pNTHeader ) ( ( IMAGE_SECTION_HEADER* )        \
    ( ( ULONG_PTR ) ( m_pNTHeader ) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ( m_pNTHeader )->FileHeader.SizeOfOptionalHeader   \
    ) )

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_SNAP_BY_ORDINAL( Ordinal ) ( ( Ordinal & IMAGE_ORDINAL_FLAG32 ) != 0 )
#define IMAGE_ORDINAL( Ordinal ) ( Ordinal & 0xffff )