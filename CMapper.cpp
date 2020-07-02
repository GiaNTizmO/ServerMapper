#include "CMapper.hpp"

#include <cstring>
#include <fstream>
#include <iterator>
#include <utility>

std::string m_sPath = "cheat.dll";

std::uint64_t* GetPtrFromRVA( std::uint64_t m_dwRVA, IMAGE_NT_HEADERS* m_pNtHeaders, uint8_t* m_aImage )
{
    auto GetSectionHeader = [ m_dwRVA, m_pNtHeaders ]( ) -> IMAGE_SECTION_HEADER*
    {
        IMAGE_SECTION_HEADER* m_pSection = IMAGE_FIRST_SECTION( m_pNtHeaders );
        for ( int i = 0; i < m_pNtHeaders->FileHeader.NumberOfSections; i++, m_pSection++ )
        {
            std::uint64_t m_dwSize = m_pSection->Misc.VirtualSize;
            if ( !m_dwSize )
                m_dwSize = m_pSection->SizeOfRawData;

            if ( ( m_dwRVA >= m_pSection->VirtualAddress ) && ( m_dwRVA < ( m_pSection->VirtualAddress + m_dwSize ) ) )
                return m_pSection;
        }

        return nullptr;
    };

    IMAGE_SECTION_HEADER* m_pSectionHeader = GetSectionHeader( );
    if ( !m_pSectionHeader )
        return nullptr;

    auto m_dwDelta = ( std::uint64_t )(m_pSectionHeader->VirtualAddress - m_pSectionHeader->PointerToRawData );
    return ( std::uint64_t* )( m_aImage + m_dwRVA - m_dwDelta );
}

void CMapper::OpenBinary( std::string &m_sSource, std::vector< std::uint8_t > &m_aData )
{
    // thanks to @Wlan, i stole his func - https://github.com/not-wlan/drvmap/blob/master/drvmap/util.cpp#L7
    std::ifstream m_strFile( m_sSource, std::ios::binary );
    m_strFile.unsetf( std::ios::skipws );
    m_strFile.seekg( 0, std::ios::end );

    const auto m_iSize = m_strFile.tellg( );

    m_strFile.seekg( 0, std::ios::beg );
    m_aData.reserve( static_cast< uint32_t >( m_iSize ) );
    m_aData.insert( m_aData.begin( ), std::istream_iterator< std::uint8_t >( m_strFile ), std::istream_iterator< std::uint8_t >( ) );
}

CMapper::CMapper( )
{
    OpenBinary( m_sPath, m_aImage );

    m_pDOSHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( m_aImage.data( ) );
    if ( !m_pDOSHeader || m_pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
        return;

    m_pNTHeaders = reinterpret_cast< IMAGE_NT_HEADERS* >( m_aImage.data( ) + m_pDOSHeader->e_lfanew );
    if ( !m_pNTHeaders || m_pNTHeaders->Signature != IMAGE_NT_SIGNATURE )
        return;

    IMAGE_IMPORT_DESCRIPTOR* m_pImportDesc = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( GetPtrFromRVA
            (
                    m_pNTHeaders->OptionalHeader.DataDirectory[ DIR_IMPORT ].VirtualAddress,
                    m_pNTHeaders,
                    m_aImage.data( )
            ) );

    for ( ; m_pImportDesc->Name; m_pImportDesc++ )
    {
        char* m_pszModule = ( char* ) GetPtrFromRVA( m_pImportDesc->Name, m_pNTHeaders, m_aImage.data( ) );

        IMAGE_THUNK_DATA* m_pThunkData = nullptr;
        IMAGE_THUNK_DATA* m_pFuncData = nullptr;

        if ( m_pImportDesc->DUMMYUNIONNAME.OriginalFirstThunk )
        {
            m_pThunkData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->DUMMYUNIONNAME.OriginalFirstThunk, m_pNTHeaders, m_aImage.data( ) );
            m_pFuncData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
        }
        else
        {
            m_pThunkData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
            m_pFuncData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
        }

        if ( !m_pThunkData || !m_pFuncData )
        {
            printf( "Image thunk or func data is NULL\n" );
            continue;
        }

        CImport m_Import;
        m_Import.m_pszModule = m_pszModule;

        for ( ; m_pThunkData->u1.AddressOfData; m_pThunkData++, m_pFuncData++ )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( m_pThunkData->u1.Ordinal ) )
            {
                short m_shOrdinal = ( short ) IMAGE_ORDINAL( m_pThunkData->u1.Ordinal );
                m_Import.m_aFunctions.emplace_back( std::to_string( m_shOrdinal ) );
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* m_pImportByName = ( IMAGE_IMPORT_BY_NAME* ) GetPtrFromRVA( ( std::uint32_t )( m_pThunkData->u1.AddressOfData ),
                                                                                                 m_pNTHeaders, m_aImage.data( ) );
                char* m_pszName = ( char* ) m_pImportByName->Name;
                m_Import.m_aFunctions.emplace_back( std::string( m_pszName ) );
            }
        }

        m_aImports.push_back( m_Import );
    }
}

std::uint64_t CMapper::GetAllocationSize( )
{
    return m_pNTHeaders->OptionalHeader.SizeOfImage;
}

void CMapper::SetAllocationBase( std::uint64_t m_dwBaseAddress )
{
    m_dwImageBase = m_dwBaseAddress;
}

void CMapper::SetupImports( std::vector< std::uint32_t > m_aAddresses )
{
    m_aProcessedImports = std::move( m_aAddresses );
}

void CMapper::ProcessMapping( )
{
    OpenBinary( m_sPath, m_aImage );
    m_pDOSHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( m_aImage.data( ) );
    if ( !m_pDOSHeader || m_pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
        return;

    m_pNTHeaders = reinterpret_cast< IMAGE_NT_HEADERS* >( m_aImage.data( ) + m_pDOSHeader->e_lfanew );
    if ( !m_pNTHeaders || m_pNTHeaders->Signature != IMAGE_NT_SIGNATURE )
        return;

    IMAGE_IMPORT_DESCRIPTOR* m_pImportDesc = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( GetPtrFromRVA
            (
                    m_pNTHeaders->OptionalHeader.DataDirectory[ DIR_IMPORT ].VirtualAddress,
                    m_pNTHeaders,
                    m_aImage.data( )
            ) );

    int m_iCurImp = 0;
    for ( ; m_pImportDesc->Name; m_pImportDesc++ )
    {
        IMAGE_THUNK_DATA* m_pThunkData = nullptr;
        IMAGE_THUNK_DATA* m_pFuncData = nullptr;

        if ( m_pImportDesc->DUMMYUNIONNAME.OriginalFirstThunk )
        {
            m_pThunkData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->DUMMYUNIONNAME.OriginalFirstThunk, m_pNTHeaders, m_aImage.data( ) );
            m_pFuncData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
        }
        else
        {
            m_pThunkData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
            m_pFuncData = ( IMAGE_THUNK_DATA* ) GetPtrFromRVA( m_pImportDesc->FirstThunk, m_pNTHeaders, m_aImage.data( ) );
        }

        if ( !m_pThunkData || !m_pFuncData )
            continue;

        for ( ; m_pThunkData->u1.AddressOfData; m_pThunkData++, m_pFuncData++ )
        {
            m_pFuncData->u1.Function = m_aProcessedImports[ m_iCurImp ];
            m_iCurImp++;
        }
    }

    IMAGE_BASE_RELOCATION* m_pBaseRelocation = reinterpret_cast< IMAGE_BASE_RELOCATION* >( GetPtrFromRVA
            (
                    m_pNTHeaders->OptionalHeader.DataDirectory[ DIR_BASERELOC ].VirtualAddress,
                    m_pNTHeaders,
                    m_aImage.data( )
            ) );

    DWORD m_dwDelta = m_dwImageBase - m_pNTHeaders->OptionalHeader.ImageBase;
    int m_nBytes = 0;
    while ( m_nBytes < m_pNTHeaders->OptionalHeader.DataDirectory[ DIR_BASERELOC ].Size )
    {
        std::uint64_t* m_pRelocBase = GetPtrFromRVA( m_pBaseRelocation->VirtualAddress, m_pNTHeaders, m_aImage.data( ) );
        DWORD m_nRelocations = ( m_pBaseRelocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
        uint16_t* m_pRelocData = ( uint16_t* )( ( DWORD ) m_pBaseRelocation + sizeof( IMAGE_BASE_RELOCATION ) );

        for ( unsigned int i = 0; i < m_nRelocations; i++ )
        {
            if ( ( ( *m_pRelocData >> 12 ) & RELOC_HIGHLOW ) )
                *( DWORD* )( ( DWORD ) m_pRelocBase + ( ( DWORD )( *m_pRelocData & 0x0FFF ) ) ) += m_dwDelta;

            m_pRelocData++;
        }

        m_nBytes += m_pBaseRelocation->SizeOfBlock;
        m_pBaseRelocation = ( IMAGE_BASE_RELOCATION* ) m_pRelocData;
    }

    IMAGE_SECTION_HEADER* m_pSectionHeader = ( IMAGE_SECTION_HEADER* )
            ( ( ( ULONG_PTR ) &m_pNTHeaders->OptionalHeader ) + m_pNTHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < m_pNTHeaders->FileHeader.NumberOfSections; i++ )
    {
        if( strcmp( ".reloc", ( char* ) m_pSectionHeader[ i ].Name ) == 0 )
        {
            void* m_pDest = m_aImage.data( ) + m_pSectionHeader[ i ].PointerToRawData;
            memset( m_pDest, 0x17, m_pSectionHeader[ i ].SizeOfRawData );
            continue;
        }

        CSection m_Section;
        m_Section.m_iVirtualAddress = m_pSectionHeader[ i ].VirtualAddress;
        m_Section.m_iPtrToRaw = m_pSectionHeader[ i ].PointerToRawData - m_pNTHeaders->OptionalHeader.SizeOfHeaders;
        m_Section.m_iSizeOfRaw = m_pSectionHeader[ i ].SizeOfRawData;
        m_PEData.m_aSections.emplace_back( m_Section );
    }

    m_PEData.m_dwEntry = m_pNTHeaders->OptionalHeader.AddressOfEntryPoint;

    m_aMappedImage.resize( m_aImage.size( ) - m_pNTHeaders->OptionalHeader.SizeOfHeaders );
    std::memcpy( m_aMappedImage.data( ), m_aImage.data( ) + m_pNTHeaders->OptionalHeader.SizeOfHeaders, m_aMappedImage.size( ) );
}

std::map< std::string, std::string > CMapper::GetImports( )
{
    std::map< std::string, std::string > m_aImportList = { };

    for ( const CImport& m_Import : m_aImports )
    {
        std::string m_sCurrentModule = std::string( m_Import.m_pszModule );

        for ( const std::string& m_sFunction : m_Import.m_aFunctions )
            m_aImportList.insert( std::make_pair( m_sCurrentModule, m_sFunction ) );
    }

    return m_aImportList;
}

CMapper::CPEData CMapper::GetData( )
{
    return m_PEData;
}

std::vector< std::uint8_t > CMapper::GetMappedImage( )
{
    return m_aMappedImage;
}
