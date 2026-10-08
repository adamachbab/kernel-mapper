#ifndef common_pdb_hpp
#define common_pdb_hpp

namespace pdb {

    constexpr DWORD    k_pdb_signature_rsds          = 0x53445352; // 'RSDS'
    constexpr NTSTATUS k_status_info_length_mismatch = 0xC0000004L;
    constexpr auto     k_system_modules_class        = 11;
    constexpr size_t   k_min_pdb_size                = 1024;

#pragma pack(push, 1)
    struct pdb_info_t {
        DWORD m_signature;
        GUID  m_guid;
        DWORD m_age;
        char  m_pdb_file_name[ 1 ];
    };
#pragma pack(pop)

    class c_com_initializer {
    public:
        c_com_initializer( ) {
            HRESULT hr = CoInitialize( NULL );
            m_initialized = SUCCEEDED( hr );
        }
        ~c_com_initializer( ) {
            if ( m_initialized ) {
                CoUninitialize( );
            }
        }
    private:
        bool m_initialized = false;
    };

    static c_com_initializer g_com_init;

    class c_pdb {
    public:
        std::string                                        m_module_bare;
        std::uint64_t                                      m_module_base = 0;
        std::vector<std::pair<std::string, std::uint64_t>> m_symbols;

        explicit c_pdb( const char* module_name ) : m_module_name( module_name ) {
            std::string s = module_name;
            auto slash = s.find_last_of( "\\/" );
            m_module_bare = ( slash != std::string::npos ) ? s.substr( slash + 1 ) : s;
            m_pe_path     = get_pe_path( module_name );
        }

        ~c_pdb( ) {
            cleanup( );
        }

        c_pdb( const c_pdb& )            = delete;
        c_pdb& operator=( const c_pdb& ) = delete;

        bool load( ) {
            m_module_base = get_kernel_module( m_module_bare.c_str( ) );
            if ( !m_module_base ) {
                klog::print_error( oxorany( "[pdb] host module not present in loaded modules list -> %s" ), m_module_bare.c_str() );
                return false;
            }

            m_pdb_path = find_cached_pdb( );
            if ( m_pdb_path.empty( ) ) {
                m_pdb_path = download_pdb( m_pe_path );
                if ( m_pdb_path.empty( ) ) {
                    klog::print_error( oxorany( "[pdb] symbol server download failed for %s" ), m_module_bare.c_str() );
                    return false;
                }
            }

            CComPtr<IDiaDataSource> p_source;
            HRESULT hr = CoCreateInstance( CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
                IID_IDiaDataSource, ( void** )&p_source );

            if ( FAILED( hr ) ) {
                const wchar_t* dia_versions[ ] = { L"msdia140.dll", L"msdia120.dll", L"msdia110.dll" };
                for ( const auto& dll : dia_versions ) {
                    hr = NoRegCoCreate( dll, CLSID_DiaSource, IID_IDiaDataSource, ( void** )&p_source );
                    if ( SUCCEEDED( hr ) ) break;
                }
                if ( FAILED( hr ) ) {
                    klog::print_error( oxorany( "[pdb] CoCreateInstance(DiaSource) + NoRegCoCreate fallbacks all failed (hr=0x%08x)" ), hr );
                    return false;
                }
            }

            std::wstring wide_path( m_pdb_path.begin( ), m_pdb_path.end( ) );
            hr = p_source->loadDataFromPdb( wide_path.c_str( ) );
            if ( FAILED( hr ) ) {
                klog::print_warn( oxorany( "[pdb] cached PDB rejected by DIA (hr=0x%08x), evicting and re-downloading" ), hr );
                DeleteFileA( m_pdb_path.c_str( ) );
                m_pdb_path = download_pdb( m_pe_path );
                if ( m_pdb_path.empty( ) ) return false;

                wide_path = std::wstring( m_pdb_path.begin( ), m_pdb_path.end( ) );
                hr = p_source->loadDataFromPdb( wide_path.c_str( ) );
                if ( FAILED( hr ) ) {
                    klog::print_error( oxorany( "[pdb] freshly downloaded PDB still unreadable (hr=0x%08x)" ), hr );
                    return false;
                }
            }

            CComPtr<IDiaSession> p_session;
            hr = p_source->openSession( &p_session );
            if ( FAILED( hr ) ) {
                klog::print_error( oxorany( "[pdb] IDiaDataSource::openSession returned hr=0x%08x" ), hr );
                return false;
            }

            CComPtr<IDiaSymbol> p_global;
            hr = p_session->get_globalScope( &p_global );
            if ( FAILED( hr ) ) {
                klog::print_error( oxorany( "[pdb] IDiaSession::get_globalScope returned hr=0x%08x" ), hr );
                return false;
            }

            m_p_source  = p_source.Detach( );
            m_p_session = p_session.Detach( );
            m_p_global  = p_global.Detach( );

            if ( !enumerate_symbols( ) ) {
                klog::print_error( oxorany( "[pdb] symbol enumeration pass failed" ) );
                cleanup( );
                return false;
            }

            return true;
        }

        std::uint64_t get_symbol_address( const char* symbol_name ) const {
            for ( const auto& symbol : m_symbols ) {
                if ( symbol.first == symbol_name )
                    return m_module_base + symbol.second;
            }
            return 0;
        }

        std::uint64_t get_symbol_rva( const char* symbol_name ) const {
            return get_symbol_address( symbol_name );
        }

        std::uint64_t get_struct_size( const char* type_name ) {
            if ( !m_p_global ) return 0;

            std::wstring w_type( type_name, type_name + strlen( type_name ) );

            CComPtr<IDiaEnumSymbols> p_enum_types;
            if ( FAILED( m_p_global->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &p_enum_types ) ) || !p_enum_types )
                return 0;

            CComPtr<IDiaSymbol> p_udt;
            ULONG celt = 0;
            if ( FAILED( p_enum_types->Next( 1, &p_udt, &celt ) ) || celt != 1 || !p_udt )
                return 0;

            ULONGLONG size = 0;
            if ( FAILED( p_udt->get_length( &size ) ) )
                return 0;

            return static_cast< std::uint64_t >( size );
        }

        std::uint64_t get_struct_member( const char* type_name, const char* member_name ) {
            if ( !m_p_global ) return 0;

            std::wstring w_type  ( type_name,   type_name   + strlen( type_name   ) );
            std::wstring w_member( member_name, member_name + strlen( member_name ) );

            CComPtr<IDiaEnumSymbols> p_enum_types;
            if ( FAILED( m_p_global->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &p_enum_types ) ) || !p_enum_types )
                return 0;

            CComPtr<IDiaSymbol> p_udt;
            ULONG celt = 0;
            if ( FAILED( p_enum_types->Next( 1, &p_udt, &celt ) ) || celt != 1 || !p_udt )
                return 0;

            return find_member_in_udt( p_udt, w_member, 0 );
        }

        void dump_struct_members( const char* type_name ) {
            if ( !m_p_global ) return;
            std::wstring w_type( type_name, type_name + strlen( type_name ) );

            CComPtr<IDiaEnumSymbols> p_enum_types;
            if ( FAILED( m_p_global->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &p_enum_types ) ) || !p_enum_types )
                return;

            CComPtr<IDiaSymbol> p_udt;
            ULONG celt = 0;
            if ( FAILED( p_enum_types->Next( 1, &p_udt, &celt ) ) || celt != 1 || !p_udt )
                return;

            CComPtr<IDiaEnumSymbols> p_children;
            if ( FAILED( p_udt->findChildren( SymTagNull, nullptr, nsNone, &p_children ) ) || !p_children )
                return;

            CComPtr<IDiaSymbol> p_child;
            while ( SUCCEEDED( p_children->Next( 1, &p_child, &celt ) ) && celt == 1 ) {
                BSTR name   = nullptr;
                LONG offset = 0;
                p_child->get_name( &name );
                p_child->get_offset( &offset );
                if ( name ) {
                    char   buf[ 256 ]{};
                    size_t n = 0;
                    wcstombs_s( &n, buf, name, sizeof( buf ) - 1 );
                    klog::print_info( oxorany( "[pdb:udt]   +0x%x  %s" ), offset, buf );
                    SysFreeString( name );
                }
                p_child.Release( );
            }
        }

        static std::uint64_t get_kernel_module( const char* module_name ) {
            void*         buffer      = nullptr;
            unsigned long buffer_size = 0;

            NTSTATUS status = NtQuerySystemInformation(
                static_cast< SYSTEM_INFORMATION_CLASS >( k_system_modules_class ),
                buffer, buffer_size, &buffer_size
            );

            while ( status == k_status_info_length_mismatch ) {
                if ( buffer ) {
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    buffer = nullptr;
                }
                buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                if ( !buffer ) {
                    return 0;
                }
                status = NtQuerySystemInformation(
                    static_cast< SYSTEM_INFORMATION_CLASS >( k_system_modules_class ),
                    buffer, buffer_size, &buffer_size
                );
            }

            if ( !NT_SUCCESS( status ) || !buffer ) {
                if ( buffer ) VirtualFree( buffer, 0, MEM_RELEASE );
                return 0;
            }

            const auto modules = reinterpret_cast< rtl_process_modules_t* >( buffer );
            for ( auto idx = 0u; idx < modules->m_count; ++idx ) {
                const auto current_module_name = std::string(
                    reinterpret_cast< char* >( modules->m_modules[ idx ].m_full_path ) +
                    modules->m_modules[ idx ].m_offset_to_file_name
                );
                if ( !_stricmp( current_module_name.c_str( ), module_name ) ) {
                    const auto module_base = reinterpret_cast< std::uint64_t >( modules->m_modules[ idx ].m_image_base );
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    return module_base;
                }
            }

            VirtualFree( buffer, 0, MEM_RELEASE );
            return 0;
        }

    private:
        std::string m_module_name;
        std::string m_pe_path;
        std::string m_pdb_path;

        IDiaDataSource* m_p_source  = nullptr;
        IDiaSession*    m_p_session = nullptr;
        IDiaSymbol*     m_p_global  = nullptr;

        std::uint64_t find_member_in_udt( IDiaSymbol* p_udt, const std::wstring& member_name, LONG base_offset ) {
            CComPtr<IDiaEnumSymbols> p_enum_data;
            if ( SUCCEEDED( p_udt->findChildren( SymTagData, member_name.c_str( ), nsfCaseInsensitive, &p_enum_data ) ) && p_enum_data ) {
                CComPtr<IDiaSymbol> p_member;
                ULONG celt = 0;
                if ( SUCCEEDED( p_enum_data->Next( 1, &p_member, &celt ) ) && celt == 1 && p_member ) {
                    LONG offset = 0;
                    if ( SUCCEEDED( p_member->get_offset( &offset ) ) )
                        return static_cast< std::uint64_t >( base_offset + offset );
                }
            }

            CComPtr<IDiaEnumSymbols> p_enum_bases;
            if ( FAILED( p_udt->findChildren( SymTagBaseClass, nullptr, nsNone, &p_enum_bases ) ) || !p_enum_bases )
                return 0;

            CComPtr<IDiaSymbol> p_base;
            ULONG celt = 0;
            while ( SUCCEEDED( p_enum_bases->Next( 1, &p_base, &celt ) ) && celt == 1 ) {
                LONG base_off = 0;
                p_base->get_offset( &base_off );

                CComPtr<IDiaSymbol> p_base_type;
                if ( SUCCEEDED( p_base->get_type( &p_base_type ) ) && p_base_type ) {
                    auto result = find_member_in_udt( p_base_type, member_name, base_offset + base_off );
                    if ( result ) return result;
                }
                p_base.Release( );
            }

            return 0;
        }

        std::string get_pe_path( const char* module_name ) const {
            return std::string( std::getenv( "systemroot" ) ) + "\\System32\\" + module_name;
        }

        std::string get_module_prefix( ) const {
            std::string prefix = m_module_bare;
            auto dot = prefix.rfind( '.' );
            if ( dot != std::string::npos )
                prefix = prefix.substr( 0, dot );
            for ( auto& c : prefix )
                c = static_cast< char >( tolower( static_cast< unsigned char >( c ) ) );
            return prefix;
        }

        std::string find_cached_pdb( ) {
            char dir[ MAX_PATH ]{};
            if ( !GetCurrentDirectoryA( sizeof( dir ), dir ) )
                return "";

            std::string pattern = std::string( dir ) + "\\" + get_module_prefix( ) + "_*.pdb";

            WIN32_FIND_DATAA fd{};
            HANDLE h = FindFirstFileA( pattern.c_str( ), &fd );
            if ( h == INVALID_HANDLE_VALUE )
                return "";

            std::string cached = std::string( dir ) + "\\" + fd.cFileName;
            FindClose( h );

            std::ifstream v( cached, std::ios::binary | std::ios::ate );
            if ( !v.is_open( ) || v.tellg( ) < static_cast< std::streampos >( k_min_pdb_size ) )
                return "";

            return cached;
        }

        std::string download_pdb( const std::string& pe_path ) {
            if ( pe_path.empty( ) ) {
                klog::print_error( oxorany( "[pdb:download] PE path argument is empty" ) );
                return "";
            }

            char download_dir[ MAX_PATH ]{};
            if ( !GetCurrentDirectoryA( sizeof( download_dir ), download_dir ) ) {
                klog::print_error( oxorany( "[pdb:download] GetCurrentDirectoryA failed (gle=0x%x)" ), ::GetLastError() );
                return "";
            }

            std::string download_path = download_dir;
            if ( download_path.back( ) != '\\' )
                download_path += "\\";

            std::ifstream file( pe_path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) ) {
                klog::print_error( oxorany( "[pdb:download] cannot open PE on disk -> %s" ), pe_path.c_str( ) );
                return "";
            }

            auto size = file.tellg( );
            if ( size <= 0 ) {
                klog::print_error( oxorany( "[pdb:download] PE file size is zero" ) );
                return "";
            }

            file.seekg( 0, std::ios::beg );
            std::vector<char> buffer( size );
            if ( !file.read( buffer.data( ), size ) ) {
                klog::print_error( oxorany( "[pdb:download] PE read into buffer failed" ) );
                return "";
            }

            if ( buffer.size( ) < sizeof( IMAGE_DOS_HEADER ) ) {
                klog::print_error( oxorany( "[pdb:download] PE smaller than IMAGE_DOS_HEADER - not a valid image" ) );
                return "";
            }

            auto* p_dos = reinterpret_cast< IMAGE_DOS_HEADER* >( buffer.data( ) );
            if ( p_dos->e_magic != IMAGE_DOS_SIGNATURE ) {
                klog::print_error( oxorany( "[pdb:download] DOS signature mismatch (expected MZ)" ) );
                return "";
            }

            if ( buffer.size( ) < static_cast< size_t >( p_dos->e_lfanew ) + sizeof( IMAGE_NT_HEADERS ) ) {
                klog::print_error( oxorany( "[pdb:download] e_lfanew points beyond buffer bounds" ) );
                return "";
            }

            auto* p_nt = reinterpret_cast< IMAGE_NT_HEADERS* >( buffer.data( ) + p_dos->e_lfanew );
            if ( p_nt->Signature != IMAGE_NT_SIGNATURE ) {
                klog::print_error( oxorany( "[pdb:download] NT signature mismatch (expected PE\\0\\0)" ) );
                return "";
            }

            const bool is_x86 = ( p_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 );
            auto* p_opt32 = reinterpret_cast< IMAGE_OPTIONAL_HEADER32* >( &p_nt->OptionalHeader );
            auto* p_opt64 = reinterpret_cast< IMAGE_OPTIONAL_HEADER64* >( &p_nt->OptionalHeader );
            const auto image_size   = is_x86 ? p_opt32->SizeOfImage   : p_opt64->SizeOfImage;
            const auto headers_size = is_x86 ? p_opt32->SizeOfHeaders : p_opt64->SizeOfHeaders;

            auto image_buffer = std::make_unique<BYTE[ ]>( image_size );
            if ( !image_buffer ) {
                klog::print_error( oxorany( "[pdb:download] heap allocation for mapped image failed" ) );
                return "";
            }

            std::memcpy( image_buffer.get( ), buffer.data( ), headers_size );

            auto* p_section = IMAGE_FIRST_SECTION( p_nt );
            for ( UINT i = 0; i < p_nt->FileHeader.NumberOfSections; ++i, ++p_section ) {
                if ( p_section->SizeOfRawData ) {
                    std::memcpy(
                        image_buffer.get( ) + p_section->VirtualAddress,
                        buffer.data( )      + p_section->PointerToRawData,
                        p_section->SizeOfRawData );
                }
            }

            IMAGE_DATA_DIRECTORY* p_data_dir = is_x86
                ? &p_opt32->DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ]
                : &p_opt64->DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

            if ( !p_data_dir->Size ) {
                klog::print_error( oxorany( "[pdb:download] IMAGE_DIRECTORY_ENTRY_DEBUG is empty" ) );
                return "";
            }

            auto* p_debug_dir = reinterpret_cast< IMAGE_DEBUG_DIRECTORY* >(
                image_buffer.get( ) + p_data_dir->VirtualAddress );

            if ( p_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW ) {
                klog::print_error( oxorany( "[pdb:download] debug directory type is not IMAGE_DEBUG_TYPE_CODEVIEW" ) );
                return "";
            }

            auto* p_pdb_info = reinterpret_cast< pdb_info_t* >(
                image_buffer.get( ) + p_debug_dir->AddressOfRawData );

            if ( p_pdb_info->m_signature != k_pdb_signature_rsds ) {
                klog::print_error( oxorany( "[pdb:download] CodeView record missing RSDS magic" ) );
                return "";
            }

            wchar_t w_guid[ 100 ]{};
            if ( !StringFromGUID2( p_pdb_info->m_guid, w_guid, 100 ) ) {
                klog::print_error( oxorany( "[pdb:download] StringFromGUID2 conversion failed" ) );
                return "";
            }

            char   a_guid[ 100 ]{};
            size_t l_guid = 0;
            wcstombs_s( &l_guid, a_guid, w_guid, sizeof( a_guid ) );

            char guid_filtered[ 256 ]{};
            for ( size_t i = 0; i < l_guid; ++i ) {
                char c = a_guid[ i ];
                if ( ( c >= '0' && c <= '9' ) || ( c >= 'A' && c <= 'F' ) || ( c >= 'a' && c <= 'f' ) )
                    guid_filtered[ strlen( guid_filtered ) ] = c;
            }

            char age[ 16 ]{};
            sprintf_s( age, "%X", p_pdb_info->m_age );

            std::string url = "https://msdl.microsoft.com/download/symbols/";
            url += p_pdb_info->m_pdb_file_name;
            url += "/";
            url += guid_filtered;
            url += age;
            url += "/";
            url += p_pdb_info->m_pdb_file_name;

            std::string pdb_path = download_path + get_module_prefix( ) + "_" + guid_filtered + age + ".pdb";
            HRESULT hr = URLDownloadToFileA( NULL, url.c_str( ), pdb_path.c_str( ), NULL, NULL );
            if ( FAILED( hr ) ) {
                klog::print_error( oxorany( "[pdb:download] SymbolServerW HTTP transfer failed (hr=0x%08x)" ), hr );
                return "";
            }

            std::ifstream verify( pdb_path, std::ios::binary | std::ios::ate );
            if ( !verify.is_open( ) || verify.tellg( ) < static_cast< std::streampos >( k_min_pdb_size ) ) {
                klog::print_error( oxorany( "[pdb:download] downloaded PDB is truncated or below sanity threshold" ) );
                DeleteFileA( pdb_path.c_str( ) );
                return "";
            }
            verify.close( );

            return pdb_path;
        }

        bool enumerate_symbols( ) {
            if ( !m_p_global ) return false;

            CComPtr<IDiaEnumSymbols> p_enum_symbols;
            HRESULT hr = m_p_global->findChildren( SymTagNull, NULL, nsNone, &p_enum_symbols );
            if ( FAILED( hr ) ) {
                klog::print_error( oxorany( "[pdb] findChildren(SymTagPublicSymbol) failed (hr=0x%08x)" ), hr );
                return false;
            }

            CComPtr<IDiaSymbol> p_symbol;
            ULONG celt = 0;
            while ( SUCCEEDED( p_enum_symbols->Next( 1, &p_symbol, &celt ) ) && celt == 1 ) {
                BSTR name;
                if ( SUCCEEDED( p_symbol->get_name( &name ) ) ) {
                    DWORD rva = 0;
                    if ( SUCCEEDED( p_symbol->get_relativeVirtualAddress( &rva ) ) ) {
                        char   buf[ 1024 ]{};
                        size_t converted = 0;
                        wcstombs_s( &converted, buf, name, sizeof( buf ) - 1 );
                        if ( converted > 0 && buf[ 0 ] != '\0' )
                            m_symbols.emplace_back( buf, rva );
                    }
                    SysFreeString( name );
                }
                p_symbol.Release( );
            }

            return !m_symbols.empty( );
        }

        void cleanup( ) {
            if ( m_p_global  ) { m_p_global ->Release( ); m_p_global  = nullptr; }
            if ( m_p_session ) { m_p_session->Release( ); m_p_session = nullptr; }
            if ( m_p_source  ) { m_p_source ->Release( ); m_p_source  = nullptr; }
        }
    };

} // namespace pdb

#endif // common_pdb_hpp