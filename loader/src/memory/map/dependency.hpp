#ifndef map_dependency_dependency_hpp
#define map_dependency_dependency_hpp

namespace map {

    class c_dependency {
    public:
        c_dependency() = default;
        ~c_dependency() = default;

        explicit c_dependency( const std::string& file_path )
            : m_dependency_path( file_path ), m_from_file( true ) {}

        explicit c_dependency( const std::vector<std::uint8_t>& raw_bytes )
            : m_dependency_image( raw_bytes ), m_from_file( false ) {}

        c_dependency( const c_dependency& )            = delete;
        c_dependency& operator=( const c_dependency& ) = delete;

        bool load() {
            if ( !m_from_file ) {
                if ( m_dependency_image.empty() ) {
                    klog::print_error( oxorany( "[dependency] in-memory image buffer is empty" ) );
                    return false;
                }
                return parse_pe_headers();
            }

            std::ifstream dep( m_dependency_path, std::ios::binary | std::ios::ate );
            if ( !dep.is_open() ) {
                klog::print_error( oxorany( "[dependency] fopen failed for payload -> %s" ), m_dependency_path.c_str() );
                return false;
            }

            const auto dep_size = dep.tellg();
            if ( dep_size <= 0 ) {
                klog::print_error( oxorany( "[dependency] payload reports zero or negative size on disk" ) );
                return false;
            }

            m_dependency_image.resize( static_cast<std::size_t>( dep_size ) );

            dep.seekg( 0, std::ios::beg );
            if ( !dep.read( reinterpret_cast<char*>( m_dependency_image.data() ), dep_size ) ) {
                klog::print_error( oxorany( "[dependency] read of payload bytes failed mid-way" ) );
                m_dependency_image.clear();
                return false;
            }

            return parse_pe_headers();
        }

        std::uint64_t get_entry_point() {
            const auto entry_rva = m_nt_headers->m_address_of_entry_point;
            for ( std::uint32_t idx = 0; idx < get_section_count(); ++idx ) {
                auto section = get_section( idx );
                if ( entry_rva >= section->m_virtual_address &&
                     entry_rva <  section->m_virtual_address + section->m_virtual_size ) {
                    klog::print_info( oxorany( "[dependency] entry point rva=0x%x lives inside section '%s'" ), entry_rva, section->m_name );
                    break;
                }
            }

            return entry_rva;
        }

        template <typename t>
        t rva_to_va( std::uint64_t rva ) {
            if ( rva < static_cast<std::uint64_t>( m_nt_headers->m_size_of_headers ) )
                return reinterpret_cast<t>( m_dependency_image.data() + rva );

            auto* first_section = m_section_header;
            for ( auto* section = first_section;
                  section < first_section + m_nt_headers->m_number_of_sections;
                  ++section ) {
                const auto va           = static_cast<std::uint32_t>( section->m_virtual_address );
                const auto virtual_size = static_cast<std::uint32_t>( section->m_virtual_size );

                if ( rva >= va && rva < static_cast<std::uint64_t>( va ) + virtual_size ) {
                    const auto raw      = static_cast<std::uint32_t>( section->m_pointer_to_raw_data );
                    const auto raw_size = static_cast<std::uint32_t>( section->m_size_of_raw_data );
                    const auto delta    = static_cast<std::uint32_t>( rva - va );

                    if ( delta < raw_size )
                        return reinterpret_cast<t>( m_dependency_image.data() + raw + delta );
                    return reinterpret_cast<t>( nullptr );
                }
            }
            return reinterpret_cast<t>( nullptr );
        }

        auto get_section( std::uint32_t idx ) {
            return std::make_shared<section_header_t>( m_section_header[ idx ] );
        }

        std::vector<std::uint8_t> get_raw_image() const {
            return m_dependency_image;
        }

        std::uint64_t get_image_base() const {
            return m_nt_headers->m_image_base;
        }

        std::uint32_t get_size() const {
            return m_nt_headers->m_size_of_image;
        }

        std::uint32_t get_header_size() const {
            return m_nt_headers->m_size_of_headers;
        }

        std::uint32_t get_section_count() const {
            return m_nt_headers->m_number_of_sections;
        }

        bool is_reloc_stripped() const {
            return ( m_nt_headers->m_characteristics & IMAGE_FILE_RELOCS_STRIPPED ) != 0;
        }

        auto get_reloc_directory() const {
            return &m_nt_headers->m_base_relocation_table;
        }

        auto get_import_table() const {
            return &m_nt_headers->m_import_table;
        }

        auto get_delay_import_descriptor() const {
            return &m_nt_headers->m_delay_import_descriptor;
        }

        std::wstring get_file_name() const {
            if ( m_dependency_path.empty() )
                return {};

            const auto last_sep = m_dependency_path.find_last_of( "\\/" );
            const std::string name = ( last_sep == std::string::npos )
                ? m_dependency_path
                : m_dependency_path.substr( last_sep + 1 );
            return std::wstring( name.begin(), name.end() );
        }

    private:
        bool parse_pe_headers() {
            m_dos_header = reinterpret_cast<dos_header_t*>( m_dependency_image.data() );
            if ( !m_dos_header->is_valid() ) {
                klog::print_error( oxorany( "[dependency] payload DOS header validation failed" ) );
                m_dependency_image.clear();
                return false;
            }

            m_nt_headers = reinterpret_cast<nt_headers_t*>(
                m_dependency_image.data() + m_dos_header->m_lfanew );
            if ( !m_nt_headers->is_valid() ) {
                klog::print_error( oxorany( "[dependency] payload NT header validation failed" ) );
                m_dependency_image.clear();
                return false;
            }

            auto* nt_base  = reinterpret_cast<std::uint8_t*>( m_dependency_image.data() + m_dos_header->m_lfanew );
            auto* opt_base = nt_base + offsetof( nt_headers_t, m_magic );
            m_section_header = reinterpret_cast<section_header_t*>(
                opt_base + m_nt_headers->m_size_of_optional_header );

            if ( !m_section_header ) {
                klog::print_error( oxorany( "[dependency] section header table resolved to null pointer" ) );
                m_dependency_image.clear();
                return false;
            }

            return true;
        }

        std::string               m_dependency_path{};
        std::vector<std::uint8_t> m_dependency_image{};
        dos_header_t*             m_dos_header     = nullptr;
        nt_headers_t*             m_nt_headers     = nullptr;
        section_header_t*         m_section_header = nullptr;
        bool                      m_from_file      = true;
    };

} // namespace map

#endif // map_dependency_dependency_hpp