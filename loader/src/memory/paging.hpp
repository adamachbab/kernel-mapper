#ifndef paging_paging_hpp
#define paging_paging_hpp

namespace paging {

    constexpr std::uint64_t k_page_4kb_size   = 0x1000ULL;
    constexpr std::uint64_t k_page_2mb_size   = 0x200000ULL;
    constexpr std::uint64_t k_page_1gb_size   = 0x40000000ULL;

    constexpr std::uint64_t k_page_shift      = 12ULL;
    constexpr std::uint64_t k_page_2mb_shift  = 21ULL;
    constexpr std::uint64_t k_page_1gb_shift  = 30ULL;

    constexpr std::uint64_t k_page_4kb_mask   = 0xFFFULL;
    constexpr std::uint64_t k_page_2mb_mask   = 0x1FFFFFULL;
    constexpr std::uint64_t k_page_1gb_mask   = 0x3FFFFFFFULL;

    constexpr std::uint64_t k_pt_entries      = 512ULL;
    constexpr std::uint64_t k_dtb_scan_limit  = 0x20000000ULL;

    enum class e_page_protection_t {
        none,
        read_write,
        read_write_execute
    };

    struct pt_entries_t {
        pml4e m_pml4e;
        pdpte m_pdpte;
        pde   m_pde;
        pte   m_pte;
    };

} // namespace paging

namespace syscall { class c_syscall; }
namespace exports { class c_exports; }

namespace paging {

    class c_paging {
    public:
        std::uint64_t m_directory_table_base = 0;
        std::uint64_t m_physical_mask        = 0;

        explicit c_paging( driver::c_driver& drv ) : m_p_driver( &drv ) {}
        ~c_paging() = default;

        c_paging( const c_paging& )            = delete;
        c_paging& operator=( const c_paging& ) = delete;

        void attach_syscall( syscall::c_syscall& sc ) { m_p_syscall = &sc; }
        void attach_exports( exports::c_exports& ex ) { m_p_exports = &ex; }

        bool setup() {
            auto page_buffer = std::make_unique<std::uint8_t[]>( k_page_4kb_size );

            for ( std::uint64_t page = 0; page < k_dtb_scan_limit; page += k_page_4kb_size ) {
                if ( !m_p_driver->read_physical_memory( page, page_buffer.get(), k_page_4kb_size ) )
                    continue;

                if ( page_buffer[ 0 ] == 0xE9 && page_buffer[ 1 ] == 0x4D &&
                     page_buffer[ 2 ] == 0x06 && page_buffer[ 3 ] == 0x00 ) {
                    const std::uint64_t dtb = *reinterpret_cast<std::uint64_t*>( page_buffer.get() + 0xA0 );
                    if ( dtb && ( dtb & k_page_4kb_mask ) == 0 ) {
                        klog::print_info( oxorany( "[paging] system DTB located -> cr3=0x%llx (scanned page 0x%llx)" ), dtb, page );
                        m_directory_table_base = dtb;
                        return true;
                    }
                }
            }

            klog::print_error( oxorany( "[paging] exhausted scan window (0x%llx bytes) without finding system DTB" ), k_dtb_scan_limit );
            return false;
        }

        std::uint64_t translate_virtual_to_physical( std::uint64_t va, std::uint32_t* page_size = nullptr ) {
            pt_entries_t entries;
            if ( !walk_page_tables( entries, va ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size ) {
                if ( page_size ) *page_size = static_cast<std::uint32_t>( k_page_1gb_size );
                return ( entries.m_pdpte.hard.pfn << k_page_shift ) + ( va & k_page_1gb_mask );
            }

            if ( entries.m_pde.hard.page_size ) {
                if ( page_size ) *page_size = static_cast<std::uint32_t>( k_page_2mb_size );
                return ( entries.m_pde.hard.pfn << k_page_shift ) + ( va & k_page_2mb_mask );
            }

            if ( page_size ) *page_size = static_cast<std::uint32_t>( k_page_4kb_size );
            return ( entries.m_pte.hard.pfn << k_page_shift ) + ( va & k_page_4kb_mask );
        }

        std::uint64_t get_pte_physical_address( std::uint64_t va ) {
            pt_entries_t entries{};
            if ( !walk_page_tables( entries, va ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size || entries.m_pde.hard.page_size )
                return 0;

            return ( entries.m_pde.hard.pfn << k_page_shift ) +
                   ( virt_addr_t{ va }.pte_index * sizeof( pte ) );
        }

        std::uint32_t get_page_size( std::uint64_t va ) {
            pt_entries_t entries;
            if ( !walk_page_tables( entries, va ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size )
                return static_cast<std::uint32_t>( k_page_1gb_size );

            if ( entries.m_pde.hard.page_size )
                return static_cast<std::uint32_t>( k_page_2mb_size );

            return static_cast<std::uint32_t>( k_page_4kb_size );
        }

        e_page_protection_t get_page_protection( std::uint64_t va ) {
            pt_entries_t entries;
            if ( !walk_page_tables( entries, va ) )
                return e_page_protection_t::none;

            if ( entries.m_pte.hard.read_write )
                return e_page_protection_t::read_write;
            if ( !entries.m_pte.hard.no_execute )
                return e_page_protection_t::read_write_execute;

            return e_page_protection_t::none;
        }

        bool read_virtual_memory( std::uint64_t va, void* buffer, std::size_t size ) {
            auto     remaining  = size;
            auto*    dst        = static_cast<std::uint8_t*>( buffer );
            auto     current_va = va;

            while ( remaining > 0 ) {
                const auto pa = translate_virtual_to_physical( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & k_page_4kb_mask;
                const auto chunk       = std::min<std::size_t>( remaining, k_page_4kb_size - page_offset );

                if ( !m_p_driver->read_physical_memory( pa, dst, chunk ) )
                    return false;

                current_va += chunk;
                dst        += chunk;
                remaining  -= chunk;
            }

            return true;
        }

        bool walk_page_tables( pt_entries_t& entries, std::uint64_t va ) {
            const virt_addr_t addr{ va };

            if ( !m_p_driver->read_physical_memory(
                    m_directory_table_base + ( addr.pml4e_index * sizeof( pml4e ) ),
                    &entries.m_pml4e, sizeof( pml4e ) ) )
                return false;

            if ( !entries.m_pml4e.hard.present )
                return false;

            if ( !m_p_driver->read_physical_memory(
                    ( entries.m_pml4e.hard.pfn << k_page_shift ) + ( addr.pdpte_index * sizeof( pdpte ) ),
                    &entries.m_pdpte, sizeof( pdpte ) ) )
                return false;

            if ( !entries.m_pdpte.hard.present )
                return false;

            if ( entries.m_pdpte.hard.page_size )
                return true;

            if ( !m_p_driver->read_physical_memory(
                    ( entries.m_pdpte.hard.pfn << k_page_shift ) + ( addr.pde_index * sizeof( pde ) ),
                    &entries.m_pde, sizeof( pde ) ) )
                return false;

            if ( !entries.m_pde.hard.present )
                return false;

            if ( entries.m_pde.hard.page_size )
                return true;

            if ( !m_p_driver->read_physical_memory(
                    ( entries.m_pde.hard.pfn << k_page_shift ) + ( addr.pte_index * sizeof( pte ) ),
                    &entries.m_pte, sizeof( pte ) ) )
                return false;

            if ( !entries.m_pte.hard.present )
                return false;

            return true;
        }

        bool split_2mb_to_4kb( std::uint64_t va ) {
            if ( !m_p_syscall || !m_p_exports ) {
                klog::print_error( oxorany( "[paging] 2MB -> 4KB split requires syscall + exports bound first" ) );
                return false;
            }

            pt_entries_t entries{};
            if ( !walk_page_tables( entries, va ) )
                return false;

            if ( !entries.m_pde.hard.present || !entries.m_pde.hard.page_size )
                return false;

            void* new_pt_va = allocate_kernel_page();
            if ( !new_pt_va ) return false;
            zero_kernel_page( new_pt_va );

            const auto new_pt_pa = get_physical_address( new_pt_va );
            if ( !new_pt_pa ) return false;

            const auto base_pfn = entries.m_pde.hard.pfn;
            for ( std::uint64_t idx = 0; idx < k_pt_entries; ++idx ) {
                pte entry{};
                entry.hard.present            = 1;
                entry.hard.read_write         = entries.m_pde.hard.read_write;
                entry.hard.user_supervisor    = entries.m_pde.hard.user_supervisor;
                entry.hard.page_write_through = entries.m_pde.hard.page_write_through;
                entry.hard.cached_disable     = entries.m_pde.hard.cached_disable;
                entry.hard.global             = entries.m_pde.hard.global;
                entry.hard.no_execute         = 0;
                entry.hard.pfn                = base_pfn + idx;

                const auto pte_pa = new_pt_pa + ( idx * sizeof( pte ) );
                if ( !m_p_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                    return false;
            }

            pde new_pde{};
            new_pde.hard.present            = 1;
            new_pde.hard.read_write         = entries.m_pde.hard.read_write;
            new_pde.hard.user_supervisor    = entries.m_pde.hard.user_supervisor;
            new_pde.hard.page_write_through = entries.m_pde.hard.page_write_through;
            new_pde.hard.cached_disable     = entries.m_pde.hard.cached_disable;
            new_pde.hard.page_size          = 0;
            new_pde.hard.no_execute         = 0;
            new_pde.hard.pfn                = new_pt_pa >> k_page_shift;

            const virt_addr_t addr{ va };
            if ( !write_pt_entry( entries.m_pdpte, addr.pde_index, new_pde ) )
                return false;

            flush_caches();
            return true;
        }

        bool split_1gb_to_4kb( std::uint64_t va ) {
            if ( !m_p_syscall || !m_p_exports ) {
                klog::print_error( oxorany( "[paging] 1GB -> 4KB split requires syscall + exports bound first" ) );
                return false;
            }

            pt_entries_t entries{};
            if ( !walk_page_tables( entries, va ) )
                return false;

            if ( !entries.m_pdpte.hard.present || !entries.m_pdpte.hard.page_size )
                return false;

            void* new_pd_va = allocate_kernel_page();
            if ( !new_pd_va ) return false;

            const auto new_pd_pa = get_physical_address( new_pd_va );
            if ( !new_pd_pa ) return false;

            const auto base_pfn = entries.m_pdpte.hard.pfn;
            for ( std::uint64_t pd_idx = 0; pd_idx < k_pt_entries; ++pd_idx ) {
                void* new_pt_va = allocate_kernel_page();
                if ( !new_pt_va ) return false;

                const auto new_pt_pa = get_physical_address( new_pt_va );
                if ( !new_pt_pa ) return false;

                const auto pd_base_pfn = base_pfn + ( pd_idx * k_pt_entries );
                for ( std::uint64_t pt_idx = 0; pt_idx < k_pt_entries; ++pt_idx ) {
                    pte entry{};
                    entry.hard.present            = 1;
                    entry.hard.read_write         = entries.m_pdpte.hard.read_write;
                    entry.hard.user_supervisor    = entries.m_pdpte.hard.user_supervisor;
                    entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                    entry.hard.cached_disable     = entries.m_pdpte.hard.cached_disable;
                    entry.hard.no_execute         = 0;
                    entry.hard.pfn                = pd_base_pfn + pt_idx;

                    const auto pte_pa = new_pt_pa + ( pt_idx * sizeof( pte ) );
                    if ( !m_p_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                        return false;
                }

                pde pd_entry{};
                pd_entry.hard.present            = 1;
                pd_entry.hard.read_write         = entries.m_pdpte.hard.read_write;
                pd_entry.hard.user_supervisor    = entries.m_pdpte.hard.user_supervisor;
                pd_entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                pd_entry.hard.cached_disable     = entries.m_pdpte.hard.cached_disable;
                pd_entry.hard.page_size          = 0;
                pd_entry.hard.no_execute         = 0;
                pd_entry.hard.pfn                = new_pt_pa >> k_page_shift;

                const auto pde_pa = new_pd_pa + ( pd_idx * sizeof( pde ) );
                if ( !m_p_driver->write_physical_memory( pde_pa, &pd_entry, sizeof( pde ) ) )
                    return false;
            }

            pdpte new_pdpte{};
            new_pdpte.hard.present            = 1;
            new_pdpte.hard.read_write         = entries.m_pdpte.hard.read_write;
            new_pdpte.hard.user_supervisor    = entries.m_pdpte.hard.user_supervisor;
            new_pdpte.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
            new_pdpte.hard.cached_disable     = entries.m_pdpte.hard.cached_disable;
            new_pdpte.hard.page_size          = 0;
            new_pdpte.hard.no_execute         = 0;
            new_pdpte.hard.pfn                = new_pd_pa >> k_page_shift;

            const virt_addr_t addr{ va };
            if ( !write_pt_entry( entries.m_pml4e, addr.pdpte_index, new_pdpte ) )
                return false;

            flush_caches();
            return true;
        }

    private:
        driver::c_driver*   m_p_driver  = nullptr;
        syscall::c_syscall* m_p_syscall = nullptr;
        exports::c_exports* m_p_exports = nullptr;

        template <typename parent_t, typename entry_t>
        bool write_pt_entry( const parent_t& parent, std::size_t index, const entry_t& entry ) {
            const auto pa = ( parent.hard.pfn << k_page_shift ) + ( index * sizeof( entry_t ) );
            return m_p_driver->write_physical_memory( pa, &entry, sizeof( entry_t ) );
        }

        void* allocate_kernel_page();
        std::uint64_t get_physical_address( void* kernel_va );
        void zero_kernel_page( void* kernel_va );
        void flush_caches();
    };

} // namespace paging

#endif // paging_paging_hpp