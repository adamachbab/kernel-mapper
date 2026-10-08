#ifndef map_allocator_allocator_hpp
#define map_allocator_allocator_hpp

namespace map {

    constexpr std::uint32_t k_section_characteristic_discardable = 0x02000000;
    constexpr std::uint32_t k_section_headers_offset_from_opt    = 0x18;

    class c_page_candidate {
    public:
        std::uint64_t m_base_address = 0;
        std::uint32_t m_unused_space = 0;
        bool          m_1gb_page     = false;
        bool          m_2mb_page     = false;
        bool          m_executable   = false;
        bool          m_writable     = false;
    };

    class c_allocator {
    public:
        explicit c_allocator( driver::c_driver& drv, paging::c_paging& pg, pdb::c_pdb& pdb )
            : m_p_driver( &drv ), m_p_paging( &pg ), m_p_pdb( &pdb ) {}

        ~c_allocator() = default;

        c_allocator( const c_allocator& )            = delete;
        c_allocator& operator=( const c_allocator& ) = delete;

        std::uint64_t find_unused_space( std::uint64_t section_base,
                                        std::uint32_t section_size,
                                        std::size_t   space_size ) {
            if ( section_size < space_size )
                return 0;

            auto section_data = std::make_unique<std::uint8_t[]>( section_size );
            if ( !m_p_paging->read_virtual_memory( section_base, section_data.get(), section_size ) )
                return 0;

            for ( std::uint32_t idx = 0; idx <= section_size - space_size; ) {
                bool found_space = true;
                for ( std::uint32_t j = 0; j < space_size; ++j ) {
                    if ( section_data[ idx + j ] != 0x00 ) {
                        found_space = false;
                        idx += j + 1;
                        break;
                    }
                }

                if ( found_space )
                    return section_base + idx;
            }

            return 0;
        }

        std::uint64_t allocate_large_page( std::size_t size ) {
            std::vector<c_page_candidate> page_candidates;
            const auto module_base = m_p_pdb->m_module_base;

            dos_header_t dos_header;
            if ( !m_p_paging->read_virtual_memory( module_base, &dos_header, sizeof( dos_header ) ) ) {
                klog::print_error( oxorany( "[allocator] failed to read DOS header from host module at 0x%llx" ), module_base );
                return 0;
            }
            if ( dos_header.m_magic != pe_magic_t::dos_header ) {
                klog::print_error( oxorany( "[allocator] host module DOS magic mismatch at 0x%llx" ), module_base );
                return 0;
            }

            nt_headers_t nt_headers;
            if ( !m_p_paging->read_virtual_memory( module_base + dos_header.m_lfanew,
                                                   &nt_headers, sizeof( nt_headers ) ) ) {
                klog::print_error( oxorany( "[allocator] failed to read NT headers of host module at 0x%llx" ), module_base );
                return 0;
            }
            if ( nt_headers.m_signature != pe_magic_t::nt_headers ||
                 nt_headers.m_magic     != pe_magic_t::opt_header ) {
                klog::print_error( oxorany( "[allocator] host module PE/OPT magic mismatch at 0x%llx" ), module_base );
                return 0;
            }

            const auto section_headers_va = ( module_base + dos_header.m_lfanew )
                + nt_headers.m_size_of_optional_header + k_section_headers_offset_from_opt;

            for ( std::uint16_t idx = 0; idx < nt_headers.m_number_of_sections; ++idx ) {
                section_header_t section_header;
                if ( !m_p_paging->read_virtual_memory(
                        section_headers_va + ( idx * sizeof( section_header_t ) ),
                        &section_header, sizeof( section_header ) ) )
                    continue;

                if ( section_header.m_characteristics & k_section_characteristic_discardable )
                    continue;

                const auto section_base = module_base + section_header.m_virtual_address;
                const auto section_size = section_header.m_virtual_size;

                std::vector<std::uint8_t> section_data( section_size );
                if ( !m_p_paging->read_virtual_memory( section_base, section_data.data(), section_size ) )
                    continue;

                const auto target_address = find_unused_space( section_base, section_size, size );
                if ( !target_address )
                    continue;

                const auto page_size    = m_p_paging->get_page_size( target_address );
                const auto page_protect = m_p_paging->get_page_protection( target_address );
                const auto zero_count   = std::count( section_data.begin(), section_data.end(), 0x00 );

                c_page_candidate candidate;
                candidate.m_base_address = target_address;
                candidate.m_unused_space = static_cast<std::uint32_t>( zero_count );
                candidate.m_1gb_page     = page_size == paging::k_page_1gb_size;
                candidate.m_2mb_page     = page_size == paging::k_page_2mb_size;
                candidate.m_executable   = page_protect == paging::e_page_protection_t::read_write_execute;
                candidate.m_writable     = ( page_protect == paging::e_page_protection_t::read_write ) ||
                                           ( page_protect == paging::e_page_protection_t::read_write_execute );

                page_candidates.emplace_back( candidate );
            }

            for ( auto& candidate : page_candidates ) {
                const auto target_address = candidate.m_base_address;
                if ( !candidate.m_executable )
                    klog::print_warn( oxorany( "[allocator] slot candidate 0x%llx is not executable - will fix via PTE rewrite" ), target_address );

                if ( candidate.m_1gb_page ) {
                    if ( !m_p_paging->split_1gb_to_4kb( target_address ) ) {
                        klog::print_error( oxorany( "[allocator] 1GB huge page split failed at 0x%llx" ), target_address );
                        return 0;
                    }
                }
                else if ( candidate.m_2mb_page ) {
                    if ( !m_p_paging->split_2mb_to_4kb( target_address ) ) {
                        klog::print_error( oxorany( "[allocator] 2MB large page split failed at 0x%llx" ), target_address );
                        return 0;
                    }
                }

                const auto pte_address = m_p_paging->get_pte_physical_address( target_address );
                if ( !pte_address )
                    continue;

                if ( !m_p_paging->translate_virtual_to_physical( target_address ) )
                    continue;

                klog::print_info( oxorany( "[allocator] carved kernel slot -> va=0x%llx (unused=0x%x bytes)" ),
                                  target_address, candidate.m_unused_space );
                return target_address;
            }

            klog::print_error( oxorany( "[allocator] no viable code cave across %d scanned sections" ),
                               nt_headers.m_number_of_sections );
            klog::print_warn( oxorany( "[allocator] if you already mapped once this session, reboot before retrying" ) );
            return 0;
        }

    private:
        driver::c_driver* m_p_driver = nullptr;
        paging::c_paging* m_p_paging = nullptr;
        pdb::c_pdb*       m_p_pdb    = nullptr;
    };

} // namespace map

#endif // map_allocator_allocator_hpp