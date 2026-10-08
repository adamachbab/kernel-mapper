#ifndef map_map_hpp
#define map_map_hpp

namespace map {

    class c_map {
    public:
        explicit c_map( driver::c_driver&   drv,
                        paging::c_paging&   pg,
                        syscall::c_syscall& sc,
                        pdb::c_pdb&         ntos,
                        exports::c_exports& exp,
                        c_allocator&        alloc,
                        std::shared_ptr<c_dependency> dependency )
            : m_p_driver   ( &drv   )
            , m_p_paging   ( &pg    )
            , m_p_syscall  ( &sc    )
            , m_p_pdb      ( &ntos  )
            , m_p_exports  ( &exp   )
            , m_p_allocator( &alloc )
            , m_dependency ( dependency ) {}

        ~c_map() = default;

        c_map( const c_map& )            = delete;
        c_map& operator=( const c_map& ) = delete;

        bool create() {
            const auto dep_size = m_dependency->get_size();
            m_mapped_image.resize( dep_size );
            std::memset( m_mapped_image.data(), 0, dep_size );

            m_dependency_base = m_p_allocator->allocate_large_page( dep_size );
            if ( !m_dependency_base ) {
                klog::print_error( oxorany( "[map] no kernel slot available for payload (size=0x%zx)" ), dep_size );
                return false;
            }

            klog::print_info( oxorany( "[map] applying base relocations (delta=0x%llx)" ), m_dependency_base - m_dependency->get_image_base() );
            if ( !relocate() ) {
                klog::print_error( oxorany( "[map] base relocation stage failed" ) );
                return false;
            }

            klog::print_info( oxorany( "[map] resolving delayed + static import tables..." ) );
            map_delayed_imports();
            map_imports();

            if ( !map_sections() ) {
                klog::print_error( oxorany( "[map] section copy stage failed" ) );
                return false;
            }

            klog::print_info( oxorany( "[map] committing image to kernel memory (size=0x%zx)" ), m_mapped_image.size() );
            if ( !write_image_to_kernel() ) {
                klog::print_error( oxorany( "[map] write to kernel memory failed mid-transfer" ) );
                return false;
            }

            klog::print_info( oxorany( "[map] module successfully mapped -> kernel_va=0x%llx" ), m_dependency_base );
            return true;
        }

        bool execute() {
            m_entry_point = m_dependency->get_entry_point();
            if ( !m_entry_point ) {
                klog::print_error( oxorany( "[map] payload has no entry point RVA" ) );
                return false;
            }

            map_entry_t entry{};
            c_entry_resolver resolver( *m_p_pdb );
            if ( !resolver.resolve( entry.m_pdb ) )
                return false;

            entry.m_directory_table_base = m_p_paging->m_directory_table_base;
            entry.m_ntoskrnl_base        = m_p_pdb->m_module_base;
            entry.m_image_size           = m_mapped_image.size();
            entry.m_image_base           = m_dependency_base;

            const auto entry_address = reinterpret_cast<std::uint64_t>(
                m_p_syscall->call_kernel<void*>(
                    m_p_exports->m_mm_allocate_independent_pages_ex,
                    reinterpret_cast<void*>( sizeof( entry ) ),
                    reinterpret_cast<void*>( static_cast<std::uintptr_t>( -1 ) ),
                    nullptr, nullptr ) );

            if ( !entry_address ) {
                klog::print_error( oxorany( "[map] MmAllocateIndependentPagesEx returned null for entry struct" ) );
                return false;
            }

            m_p_syscall->call_kernel<void*>(
                m_p_exports->m_memcpy,
                reinterpret_cast<void*>( entry_address ),
                &entry,
                reinterpret_cast<void*>( sizeof( entry ) ) );

            const auto result = m_p_syscall->call_kernel<bool>(
                m_dependency_base + m_entry_point,
                reinterpret_cast<void*>( entry_address ) );

            if ( result )
                klog::print_info( oxorany( "[map] payload entry point returned success" ) );
            else
                klog::print_error( oxorany( "[map] payload entry point returned failure" ) );

            return result;
        }

    private:
        driver::c_driver*             m_p_driver        = nullptr;
        paging::c_paging*             m_p_paging        = nullptr;
        syscall::c_syscall*           m_p_syscall       = nullptr;
        pdb::c_pdb*                   m_p_pdb           = nullptr;
        exports::c_exports*           m_p_exports       = nullptr;
        c_allocator*                  m_p_allocator     = nullptr;
        std::shared_ptr<c_dependency> m_dependency;
        std::uint64_t                 m_dependency_base = 0;
        std::uint64_t                 m_entry_point     = 0;
        std::vector<std::uint8_t>     m_mapped_image;

        bool relocate() {
            const auto delta_offset = m_dependency_base - m_dependency->get_image_base();

            if ( m_dependency->is_reloc_stripped() ) {
                klog::print_error( oxorany( "[map:reloc] payload was linked with IMAGE_FILE_RELOCS_STRIPPED - cannot rebase" ) );
                return false;
            }

            auto* reloc_dir = m_dependency->get_reloc_directory();
            if ( !reloc_dir ) {
                klog::print_error( oxorany( "[map:reloc] relocation data directory is missing from payload" ) );
                return false;
            }

            auto* reloc_entry = m_dependency->rva_to_va<reloc_entry_t*>( reloc_dir->m_virtual_address );
            if ( !reloc_entry ) {
                klog::print_error( oxorany( "[map:reloc] rva_to_va returned null for relocation block" ) );
                return false;
            }

            auto* reloc_end = reinterpret_cast<reloc_entry_t*>(
                reinterpret_cast<std::uint8_t*>( reloc_entry ) + reloc_dir->m_size );

            while ( reloc_entry < reloc_end && reloc_entry->m_size ) {
                const auto record_count = ( reloc_entry->m_size - 8 ) >> 1;
                klog::print_info( oxorany( "[map:reloc] patching block -> rva=0x%x, size=0x%x" ), reloc_entry->m_to_rva, reloc_entry->m_size );

                for ( std::uint32_t idx = 0; idx < record_count; ++idx ) {
                    const auto offset = reloc_entry->m_item[ idx ].m_offset % 4096;
                    const auto type   = reloc_entry->m_item[ idx ].m_type;
                    if ( type == IMAGE_REL_BASED_ABSOLUTE )
                        continue;

                    auto* reloc_addr = m_dependency->rva_to_va<std::uint8_t*>( reloc_entry->m_to_rva );
                    auto* reloc_va   = reinterpret_cast<std::uint64_t*>( reloc_addr + offset );
                    *reloc_va += delta_offset;
                }

                reloc_entry = reinterpret_cast<reloc_entry_t*>(
                    reinterpret_cast<std::uint8_t*>( reloc_entry ) + reloc_entry->m_size );
            }

            return true;
        }

        bool map_imports() {
            auto* import_table = m_dependency->get_import_table();
            if ( !import_table->m_virtual_address || !import_table->m_size ) {
                klog::print_info( oxorany( "[map:imports] payload declares no import table - skipping (expected for manual-mapped drivers)" ) );
                return true;
            }

            auto* import_desc = m_dependency->rva_to_va<import_descriptor_t*>( import_table->m_virtual_address );
            while ( import_desc->m_name ) {
                auto* module_name = m_dependency->rva_to_va<LPSTR>( import_desc->m_name );
                if ( !module_name ) {
                    klog::print_error( oxorany( "[map:imports] descriptor m_name resolved to null" ) );
                    break;
                }

                const auto import_module_base = pdb::c_pdb::get_kernel_module( module_name );
                if ( !import_module_base ) {
                    klog::print_error( oxorany( "[map:imports] kernel module not loaded -> %s" ), module_name );
                    return false;
                }

                klog::print_info( oxorany( "[map:imports] binding against %s (base=0x%llx)" ), module_name, import_module_base );

                pdb::c_pdb import_pdb( module_name );
                if ( !import_pdb.load() ) {
                    klog::print_error( oxorany( "[map:imports] PDB download/parse failed for %s" ), module_name );
                    return false;
                }

                auto* first_thunk      = m_dependency->rva_to_va<nt_image_thunk_data_t*>( import_desc->m_first_thunk );
                auto* orig_first_thunk = m_dependency->rva_to_va<nt_image_thunk_data_t*>( import_desc->m_original_first_thunk );
                if ( !orig_first_thunk || !first_thunk ) {
                    klog::print_error( oxorany( "[map:imports] IAT/INT thunks resolved to null" ) );
                    break;
                }

                while ( first_thunk->u1.address_of_data ) {
                    if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
                        klog::print_warn( oxorany( "[map:imports] ordinal-based imports are not supported" ) );
                        return false;
                    }

                    auto* ibn = m_dependency->rva_to_va<nt_image_import_name_t*>( orig_first_thunk->u1.address_of_data );
                    if ( !ibn ) {
                        klog::print_error( oxorany( "[map:imports] import-by-name entry resolved to null" ) );
                        return false;
                    }

                    first_thunk->u1.function = import_pdb.get_symbol_address( ibn->name );
                    if ( !first_thunk->u1.function ) {
                        klog::print_error( oxorany( "[map:imports] symbol not found -> %s!%s" ), module_name, ibn->name );
                        return false;
                    }

                    ++orig_first_thunk;
                    ++first_thunk;
                }

                std::memset( module_name, 0, std::strlen( module_name ) );
                ++import_desc;
            }

            return true;
        }

        bool map_delayed_imports() {
            auto* delay_descriptor = m_dependency->get_delay_import_descriptor();
            if ( !delay_descriptor->m_virtual_address || !delay_descriptor->m_size )
                return true;

            auto* delay_desc = m_dependency->rva_to_va<image_delayload_descriptor_t*>( delay_descriptor->m_virtual_address );
            while ( delay_desc->m_dll_name_rva ) {
                auto* module_name = m_dependency->rva_to_va<LPSTR>( delay_desc->m_dll_name_rva );
                if ( !module_name ) {
                    klog::print_error( oxorany( "[map:delay] delay descriptor dll name resolved to null" ) );
                    break;
                }

                const auto import_module_base = pdb::c_pdb::get_kernel_module( module_name );
                if ( !import_module_base ) {
                    klog::print_error( oxorany( "[map:delay] delay-load target not loaded -> %s" ), module_name );
                    return false;
                }

                klog::print_info( oxorany( "[map:delay] binding delay-load against %s" ), module_name );

                pdb::c_pdb import_pdb( module_name );
                if ( !import_pdb.load() ) {
                    klog::print_error( oxorany( "[map:delay] PDB download/parse failed for %s" ), module_name );
                    return false;
                }

                auto* first_thunk      = m_dependency->rva_to_va<nt_image_thunk_data_t*>( delay_desc->m_import_address_table_rva );
                auto* orig_first_thunk = m_dependency->rva_to_va<nt_image_thunk_data_t*>( delay_desc->m_import_name_table_rva );
                if ( !orig_first_thunk || !first_thunk ) {
                    klog::print_error( oxorany( "[map:delay] delay IAT/INT thunks resolved to null" ) );
                    break;
                }

                while ( first_thunk->u1.address_of_data ) {
                    if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
                        klog::print_warn( oxorany( "[map:delay] ordinal-based delay imports are not supported" ) );
                        return false;
                    }

                    auto* ibn = m_dependency->rva_to_va<nt_image_import_name_t*>( orig_first_thunk->u1.address_of_data );
                    if ( !ibn ) {
                        klog::print_error( oxorany( "[map:delay] delay import-by-name entry resolved to null" ) );
                        return false;
                    }

                    first_thunk->u1.function = import_pdb.get_symbol_address( ibn->name );
                    if ( !first_thunk->u1.function ) {
                        klog::print_error( oxorany( "[map:delay] delay symbol not found -> %s!%s" ), module_name, ibn->name );
                        return false;
                    }

                    ++orig_first_thunk;
                    ++first_thunk;
                }

                ++delay_desc;
            }

            return true;
        }

        bool map_sections() {
            const auto section_count = m_dependency->get_section_count();
            for ( std::uint32_t idx = 0; idx < section_count; ++idx ) {
                auto section = m_dependency->get_section( idx );
                if ( !section->m_virtual_address || !section->m_size_of_raw_data )
                    continue;

                auto* section_buffer = m_mapped_image.data() + section->m_virtual_address;
                auto* source_data    = m_dependency->get_raw_image().data() + section->m_pointer_to_raw_data;
                std::memcpy( section_buffer, source_data, section->m_size_of_raw_data );

                klog::print_info( oxorany( "[map:sections] copied '%s' -> rva=0x%x, size=0x%x" ),
                    section->m_name, section->m_virtual_address, section->m_size_of_raw_data );
            }

            return true;
        }

        bool write_image_to_kernel() {
            auto     remaining  = m_mapped_image.size();
            auto*    src        = m_mapped_image.data();
            auto     current_va = m_dependency_base;

            while ( remaining > 0 ) {
                const auto pa = m_p_paging->translate_virtual_to_physical( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & paging::k_page_4kb_mask;
                const auto chunk       = std::min<std::size_t>( remaining, paging::k_page_4kb_size - page_offset );

                if ( !m_p_driver->write_physical_memory( pa, src, chunk ) )
                    return false;

                current_va += chunk;
                src        += chunk;
                remaining  -= chunk;
            }

            return true;
        }
    };

} // namespace map

#endif // map_map_hpp