#include "PortableExecutable.hpp"

#include <iostream>
#include <vector>
#include <map>

class CMapper
{

private:

    struct CSection
    {
        std::uint32_t m_iVirtualAddress;
        std::uint32_t m_iPtrToRaw;
        std::uint32_t m_iSizeOfRaw;
    };

public:

    struct CPEData
    {
        std::uint64_t m_dwEntry = 0x00;
        std::vector< CSection > m_aSections = { };
    };

    CMapper( );

    std::uint64_t GetAllocationSize( );

    void SetAllocationBase( std::uint64_t m_dwBaseAddress );
    void SetupImports( std::vector< std::uint32_t > m_aAddresses );
    void ProcessMapping( );

    std::map< std::string, std::string > GetImports( );

    CPEData GetData( );

    std::vector< std::uint8_t > GetMappedImage( );

private:

    CPEData m_PEData;

    struct CImport
    {
        char* m_pszModule;
        std::vector< std::string > m_aFunctions;
    };

    std::vector< CImport > m_aImports;
    std::vector< std::uint32_t > m_aProcessedImports;

    void OpenBinary( std::string& m_sSource, std::vector< std::uint8_t >& m_aData );

    std::vector< std::uint8_t > m_aImage;

    std::uint64_t m_dwImageBase = 0x00;

    IMAGE_DOS_HEADER* m_pDOSHeader;
    IMAGE_NT_HEADERS* m_pNTHeaders;

};