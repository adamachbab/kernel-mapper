#ifndef driver_service_hpp
#define driver_service_hpp

using nt_load_driver_t   = NTSTATUS( __fastcall* )( PUNICODE_STRING );
using nt_unload_driver_t = NTSTATUS( __stdcall*  )( PUNICODE_STRING );

extern "C" NTSTATUS NTAPI NtClose( HANDLE );

namespace util {

    template <size_t n>
    inline void gen_rnd_str( wchar_t( &out )[ n ] ) {
        const wchar_t* alphabet = oxorany( L"abcdefghijklmnopqrstuvwxyz" );
        const size_t   k_len    = ::wcslen( alphabet );

        LARGE_INTEGER qpc{};
        ::QueryPerformanceCounter( &qpc );
        std::uint64_t seed = static_cast< std::uint64_t >( qpc.QuadPart ) ^ ::GetTickCount64();

        for ( size_t i = 0; i + 1 < n; ++i ) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            out[ i ] = alphabet[ ( seed >> 33 ) % k_len ];
        }
        out[ n - 1 ] = L'\0';
    }

} // namespace util

namespace service {

    constexpr DWORD    k_service_type_kernel          = 1;
    constexpr NTSTATUS k_status_image_already_loaded  = 0xC0000035;
    constexpr NTSTATUS k_status_object_name_not_found = 0xC0000034;
    constexpr size_t   k_driver_name_len              = 20;

    inline bool load_driver_privilege( bool enabled ) {
        TOKEN_PRIVILEGES privilege{};
        privilege.PrivilegeCount = 1;

        if ( !::LookupPrivilegeValueA( nullptr, oxorany( "SeLoadDriverPrivilege" ), &privilege.Privileges[ 0 ].Luid ) ) {
            klog::print_error( oxorany( "[service] LookupPrivilegeValueA(SeLoadDriverPrivilege) failed (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        HANDLE token = nullptr;
        if ( !::OpenProcessToken(
                ::GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &token ) ) {
            klog::print_error( oxorany( "[service] OpenProcessToken on current process failed (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        privilege.Privileges[ 0 ].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

        auto result = ::AdjustTokenPrivileges( token, FALSE, &privilege, sizeof( privilege ), nullptr, nullptr );
        if ( !result || ::GetLastError() == ERROR_NOT_ALL_ASSIGNED ) {
            result = ::AdjustTokenPrivileges( token, TRUE, &privilege, sizeof( privilege ), nullptr, nullptr );
        }

        ::NtClose( token );

        if ( !result || ::GetLastError() == ERROR_NOT_ALL_ASSIGNED ) {
            klog::print_error( oxorany( "[service] AdjustTokenPrivileges rejected privilege toggle (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        return true;
    }

    inline UNICODE_STRING build_driver_path( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' )
            return {};

        static wchar_t registry_path[ 80 ]{};
        std::memset( registry_path, 0, sizeof( registry_path ) );
        std::wcscat( registry_path, oxorany( L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ) );
        std::wcscat( registry_path, service_name );

        UNICODE_STRING driver_path{};
        driver_path.Length        = USHORT( std::wcslen( registry_path ) << 1 );
        driver_path.Buffer        = registry_path;
        driver_path.MaximumLength = driver_path.Length + 2;
        return driver_path;
    }

    inline std::wstring get_driver_filename( const wchar_t* service_name ) {
        HKEY key = nullptr;
        const auto full_path = std::wstring( oxorany( L"SYSTEM\\CurrentControlSet\\Services\\" ) ) + service_name;
        if ( ::RegOpenKeyW( HKEY_LOCAL_MACHINE, full_path.c_str(), &key ) != ERROR_SUCCESS )
            return L"";

        wchar_t image_path[ MAX_PATH ]{};
        DWORD   size = sizeof( image_path );
        DWORD   type = 0;

        const auto status = ::RegQueryValueExW(
            key, oxorany( L"ImagePath" ), nullptr, &type,
            reinterpret_cast< LPBYTE >( image_path ), &size );

        ::RegCloseKey( key );

        if ( status != ERROR_SUCCESS || ( type != REG_SZ && type != REG_EXPAND_SZ ) )
            return L"";

        if ( type == REG_EXPAND_SZ ) {
            wchar_t expanded[ MAX_PATH ]{};
            if ( ::ExpandEnvironmentStringsW( image_path, expanded, MAX_PATH ) )
                ::wcscpy_s( image_path, expanded );
        }

        std::wstring path( image_path );
        const wchar_t* nt_prefix = oxorany( L"\\??\\" );
        if ( path.find( nt_prefix ) == 0 )
            path.erase( 0, ::wcslen( nt_prefix ) );

        const auto pos = path.find_last_of( L'\\' );
        return ( pos != std::wstring::npos ) ? path.substr( pos + 1 ) : path;
    }

    inline bool create_service( const wchar_t* service_name, const wchar_t* registry_path ) {
        if ( !service_name || !registry_path ) {
            klog::print_error( oxorany( "[service] create_service received null service name or registry path" ) );
            return false;
        }

        HKEY services_key = nullptr;
        auto status = ::RegOpenKeyA( HKEY_LOCAL_MACHINE, oxorany( "SYSTEM\\CurrentControlSet\\Services" ), &services_key );
        if ( status != ERROR_SUCCESS ) {
            klog::print_error( oxorany( "[service] RegOpenKeyA(services) failed with status=%d" ), status );
            return false;
        }

        HKEY service_key = nullptr;
        status = ::RegCreateKeyW( services_key, service_name, &service_key );
        if ( status != ERROR_SUCCESS ) {
            ::RegCloseKey( services_key );
            klog::print_error( oxorany( "[service] RegCreateKeyW(service subkey) failed with status=%d" ), status );
            return false;
        }

        const auto path_len = ( std::wcslen( registry_path ) + 1 ) << 1;
        status = ::RegSetValueExW(
            service_key, oxorany( L"ImagePath" ), 0, REG_EXPAND_SZ,
            reinterpret_cast< const std::uint8_t* >( registry_path ),
            static_cast< DWORD >( path_len ) );

        if ( status != ERROR_SUCCESS ) {
            ::RegCloseKey( service_key );
            ::RegCloseKey( services_key );
            klog::print_error( oxorany( "[service] RegSetValueExW(ImagePath) failed with status=%d" ), status );
            return false;
        }

        const DWORD type = k_service_type_kernel;
        status = ::RegSetValueExA(
            service_key, oxorany( "Type" ), 0, REG_DWORD,
            reinterpret_cast< const std::uint8_t* >( &type ),
            sizeof( type ) );

        ::RegCloseKey( service_key );
        ::RegCloseKey( services_key );

        if ( status != ERROR_SUCCESS ) {
            klog::print_error( oxorany( "[service] RegSetValueExA(Type) failed with status=%d" ), status );
            return false;
        }

        return true;
    }

    inline bool uninstall_service( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            klog::print_error( oxorany( "[service] uninstall_service called with empty service name" ) );
            return false;
        }

        auto* nt_unload_drv = reinterpret_cast< nt_unload_driver_t >(
            ::GetProcAddress( ::GetModuleHandleA( oxorany( "ntdll.dll" ) ), oxorany( "NtUnloadDriver" ) ) );

        if ( !nt_unload_drv ) {
            klog::print_error( oxorany( "[service] NtUnloadDriver export not found in ntdll" ) );
            return false;
        }

        auto driver_nt_name = build_driver_path( service_name );
        if ( !driver_nt_name.Buffer ) {
            klog::print_error( oxorany( "[service] build_driver_path returned empty UNICODE_STRING (unload path)" ) );
            return false;
        }

        const auto status = nt_unload_drv( &driver_nt_name );
        if ( status != 0 && status != k_status_object_name_not_found )
            return false;

        HKEY services_key = nullptr;
        auto reg_status = ::RegOpenKeyA( HKEY_LOCAL_MACHINE, oxorany( "SYSTEM\\CurrentControlSet\\Services" ), &services_key );
        if ( reg_status != ERROR_SUCCESS ) {
            klog::print_error( oxorany( "[service] RegOpenKeyA(services) during uninstall failed with status=%d" ), reg_status );
            return false;
        }

        reg_status = ::RegDeleteKeyW( services_key, service_name );
        ::RegCloseKey( services_key );

        if ( reg_status != ERROR_SUCCESS ) {
            klog::print_error( oxorany( "[service] RegDeleteKeyW(service subkey) failed with status=%d" ), reg_status );
            return false;
        }

        return true;
    }

    inline bool uninstall_services() {
        HKEY services_key = nullptr;
        if ( ::RegOpenKeyA( HKEY_LOCAL_MACHINE, oxorany( "SYSTEM\\CurrentControlSet\\Services" ), &services_key ) != ERROR_SUCCESS ) {
            klog::print_error( oxorany( "[service] RegOpenKeyA(services) failed while enumerating stale services" ) );
            return false;
        }

        DWORD   index = 0;
        wchar_t service_name[ MAX_PATH ]{};

        while ( !::RegEnumKeyW( services_key, index, service_name, MAX_PATH ) ) {
            HKEY service_key = nullptr;
            if ( !::RegOpenKeyW( services_key, service_name, &service_key ) ) {
                wchar_t image_path[ MAX_PATH ]{};
                DWORD   path_size = sizeof( image_path );
                DWORD   type      = REG_EXPAND_SZ;

                if ( ::RegQueryValueExW(
                        service_key, oxorany( L"ImagePath" ), nullptr, &type,
                        reinterpret_cast< LPBYTE >( image_path ), &path_size ) == ERROR_SUCCESS ) {
                    if ( ::wcsstr( image_path, oxorany( L"\\??\\" ) ) != nullptr &&
                         ::wcsstr( image_path, oxorany( L".log"   ) ) != nullptr ) {
                        uninstall_service( service_name );
                    }
                }
                ::RegCloseKey( service_key );
            }
            ++index;
        }

        ::RegCloseKey( services_key );
        return true;
    }

    inline bool install_service( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            klog::print_error( oxorany( "[service] install_service called with empty service name" ) );
            return false;
        }

        uninstall_services();

        wchar_t registry_path[ MAX_PATH ]{};
        std::wcscat( registry_path, oxorany( L"\\??\\" ) );

        auto* file_path = &registry_path[ 4 ];
        if ( ::GetTempPathW( MAX_PATH - 4, file_path ) == 0 ) {
            klog::print_error( oxorany( "[service] GetTempPathW returned zero (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        std::wcscat( file_path, service_name );
        std::wcscat( file_path, oxorany( L".log" ) );

        if ( !create_service( service_name, registry_path ) ) {
            klog::print_error( oxorany( "[service] registry entry for driver service could not be created" ) );
            return false;
        }

        ( void )::DeleteFileW( file_path );

        if ( !::MoveFileExW( file_path, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT ) ) {
            klog::print_error( oxorany( "[service] MoveFileExW(DELAY_UNTIL_REBOOT) scheduling failed (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        HANDLE file_handle = ::CreateFileW(
            file_path,
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,
            nullptr );

        if ( file_handle == INVALID_HANDLE_VALUE ) {
            klog::print_error( oxorany( "[service] CreateFileW on dropped driver image failed (gle=0x%x)" ), ::GetLastError() );
            return false;
        }

        DWORD bytes_written = 0;
        if ( !::WriteFile( file_handle, driver_bytes, sizeof( driver_bytes ), &bytes_written, nullptr ) ||
             bytes_written != sizeof( driver_bytes ) ) {
            ::CloseHandle( file_handle );
            klog::print_error( oxorany( "[service] WriteFile on driver image incomplete or failed" ) );
            return false;
        }

        ::CloseHandle( file_handle );

        auto driver_nt_name = build_driver_path( service_name );
        if ( !driver_nt_name.Buffer ) {
            klog::print_error( oxorany( "[service] build_driver_path returned empty UNICODE_STRING (load path)" ) );
            return false;
        }

        auto* nt_load_drv = reinterpret_cast< nt_load_driver_t >(
            ::GetProcAddress( ::GetModuleHandleA( oxorany( "ntdll.dll" ) ), oxorany( "NtLoadDriver" ) ) );

        if ( !nt_load_drv ) {
            klog::print_error( oxorany( "[service] NtLoadDriver export not found in ntdll" ) );
            return false;
        }

        const auto status = nt_load_drv( &driver_nt_name );
        if ( status == k_status_image_already_loaded ) {
            klog::print_warn( oxorany( "[service] a previous instance of this driver image is still loaded" ) );
            uninstall_services();
            klog::print_warn( oxorany( "[service] stale entries purged - please reboot and relaunch the loader" ) );
            return false;
        }

        if ( status != 0 ) {
            klog::print_error( oxorany( "[service] NtLoadDriver returned NTSTATUS=0x%x" ), status );
            return false;
        }

        klog::print_info( oxorany( "[service] driver image dropped and loaded into kernel space" ) );
        return true;
    }

    class c_service {
    public:
        bool create() {
            if ( !load_driver_privilege( true ) ) {
                klog::print_error( oxorany( "[service] SeLoadDriverPrivilege could not be enabled (run as admin?)" ) );
                return false;
            }

            util::gen_rnd_str( m_driver_name );
            if ( !install_service( m_driver_name ) ) {
                load_driver_privilege( false );
                return false;
            }

            return true;
        }

        bool cleanup() {
            std::memset( driver_bytes, 0, sizeof( driver_bytes ) );
            return true;
        }

        void unload() {
            uninstall_services();
            load_driver_privilege( false );
        }

        const wchar_t* driver_name() const { return m_driver_name; }

    private:
        wchar_t m_driver_name[ k_driver_name_len ]{};

        std::uint32_t get_timestamp() const {
            auto* dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( driver_bytes );
            if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
                return 0;

            auto* nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >(
                reinterpret_cast< std::uint64_t >( driver_bytes ) + dos_header->e_lfanew );
            if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
                return 0;

            return nt_headers->FileHeader.TimeDateStamp;
        }
    };

} // namespace service

#endif // driver_service_hpp