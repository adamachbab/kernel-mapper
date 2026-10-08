#ifndef map_entry_hpp
#define map_entry_hpp

namespace map {

    struct reloc_entry_t {
        std::uint32_t m_to_rva;
        std::uint32_t m_size;
        struct {
            std::uint16_t m_offset : 12;
            std::uint16_t m_type : 4;
        } m_item[ 1 ];
    };

    struct entry_pdb_t {
        std::uint64_t m_dbg_print_ex = 0;
    };

    struct map_entry_t {
        entry_pdb_t   m_pdb;
        std::uint64_t m_directory_table_base = 0;
        std::uint64_t m_ntoskrnl_base        = 0;
        std::uint64_t m_image_size           = 0;
        std::uint64_t m_image_base           = 0;
    };

    class c_entry_resolver {
    public:
        explicit c_entry_resolver( pdb::c_pdb& pdb ) : m_p_pdb( &pdb ) {}

        bool resolve( entry_pdb_t& out ) {
            out.m_dbg_print_ex = m_p_pdb->get_symbol_address( oxorany( "DbgPrintEx" ) );

            if ( !out.m_dbg_print_ex ) {
                klog::print_error( oxorany( "[entry] DbgPrintEx symbol missing - payload would have no logging channel" ) );
                return false;
            }

            return true;
        }

    private:
        pdb::c_pdb* m_p_pdb = nullptr;
    };

} // namespace map

#endif // map_entry_hpp