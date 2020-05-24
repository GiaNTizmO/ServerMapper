#include "CMapper.hpp"

int main( )
{
    CMapper m_Mapper;
    std::uint64_t m_dwAllocationSize = m_Mapper.GetAllocationSize( ); // allocate memory for this size

    std::uint64_t m_dwAllocation = 0x1337; // address of allocation
    m_Mapper.SetAllocationBase( m_dwAllocation ); // sets allocation base to perform relocations

    std::map< std::string, std::string > m_aImports = m_Mapper.GetImports( ); // returns imports to fix, consider sending them to client using json or sth else

    std::vector< std::uint32_t > m_aImportAddresses; // contains addresses of imported functions received from client
    m_Mapper.SetupImports( m_aImportAddresses ); // setting up imports for fixing them

    m_Mapper.ProcessMapping( ); // processing mapping

    CMapper::CPEData m_PEData = m_Mapper.GetData( ); // contains data to write sections and invoke entry

    std::vector< std::uint8_t > m_aMappedImage = m_Mapper.GetMappedImage( ); // this is our mapped PE image

    return 0;
}
