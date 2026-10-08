#ifndef common_exports_hpp
#define common_exports_hpp

namespace exports {

    class c_exports {
    public:
        std::uint64_t m_mm_allocate_independent_pages_ex = 0;
        std::uint64_t m_mm_free_independent_pages        = 0;
        std::uint64_t m_mm_get_physical_address          = 0;

        std::uint64_t m_ke_invalidate_all_caches         = 0;
        std::uint64_t m_ke_flush_entire_tb               = 0;

        std::uint64_t m_memset                           = 0;
        std::uint64_t m_memcpy                           = 0;

        explicit c_exports( pdb::c_pdb& pdb ) : m_p_pdb( &pdb ) {}
        ~c_exports() = default;

        c_exports( const c_exports& )            = delete;
        c_exports& operator=( const c_exports& ) = delete;

        bool setup() {
            m_mm_allocate_independent_pages_ex = resolve( oxorany( "MmAllocateIndependentPagesEx" ) );
            m_mm_free_independent_pages        = resolve( oxorany( "MmFreeIndependentPages"       ) );
            m_mm_get_physical_address          = resolve( oxorany( "MmGetPhysicalAddress"         ) );
            m_ke_invalidate_all_caches         = resolve( oxorany( "KeInvalidateAllCaches"        ) );
            m_ke_flush_entire_tb               = resolve( oxorany( "KeFlushEntireTb"              ) );
            m_memset                           = resolve( oxorany( "memset"                      ) );
            m_memcpy                           = resolve( oxorany( "memcpy"                      ) );

            if ( !m_mm_allocate_independent_pages_ex ||
                 !m_mm_get_physical_address          ||
                 !m_ke_invalidate_all_caches         ||
                 !m_memset ) {
                klog::print_error( oxorany( "[exports] one or more mandatory kernel routines missing from PDB" ) );
                return false;
            }

            klog::print_info( oxorany( "[exports] all required kernel routines resolved (Mm*, Ke*, mem*)" ) );
            return true;
        }

    private:
        pdb::c_pdb* m_p_pdb = nullptr;

        std::uint64_t resolve( const char* name ) {
            const auto addr = m_p_pdb->get_symbol_address( name );
            if ( !addr )
                klog::print_warn( oxorany( "[exports] optional kernel symbol unresolved -> %s" ), name );
            return addr;
        }
    };

} // namespace exports

#endif // common_exports_hpp