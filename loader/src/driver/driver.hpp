#ifndef driver_driver_hpp
#define driver_driver_hpp

namespace util {

    inline bool is_physical_address_valid( std::uint64_t pa, std::size_t size ) {
        int regs[ 4 ]{};
        __cpuid( regs, 0x80000000 );
        const unsigned max_ext = static_cast< unsigned >( regs[ 0 ] );

        unsigned phys_bits = 36;
        if ( max_ext >= 0x80000008 ) {
            __cpuid( regs, 0x80000008 );
            const unsigned b = regs[ 0 ] & 0xFF;
            if ( b >= 32 && b <= 52 )
                phys_bits = b;
        }

        const auto physical_mask = ( phys_bits >= 63 )
            ? ~0ULL
            : ( ( 1ULL << phys_bits ) - 1ULL );

        if ( ( pa & ~physical_mask ) != 0 )
            return false;

        const auto end_pa = pa + ( size - 1 );
        if ( ( end_pa & ~physical_mask ) != 0 )
            return false;

        return true;
    }

} // namespace util

namespace driver {

    constexpr DWORD    k_syscall_index = 7;
    constexpr uint32_t k_ioctl_map = 0x0022E008;
    constexpr uint32_t k_ioctl_unmap = 0x0022E00C;
    constexpr size_t   k_page_size = 0x1000;
    constexpr uint64_t k_page_mask = ~0xFFFULL;
    constexpr uint64_t k_page_off_mask = 0xFFFULL;
    constexpr uint64_t k_resolve_hi_max = 0x800ULL;

#pragma pack(push, 1)
    struct map_physical_input_t {
        std::uint64_t m_physical_address;
        std::uint64_t m_size;
    };

    struct unmap_physical_input_t {
        std::uint64_t m_mapped_memory;
    };
#pragma pack(pop)

#pragma section(".text")
    __declspec( allocate( ".text" ) )
        inline const std::uint8_t g_syscall_stub[ ]{
            0x4C, 0x8B, 0x11,  // mov r10, [rcx]
            0x8B, 0x41, 0x08,  // mov eax, [rcx+8]
            0x0F, 0x05,        // syscall
            0xC3               // ret
    };

    template <typename ret_t = void, typename first_t = void*, typename... args_t>
    inline ret_t syscall( DWORD index, first_t arg = first_t{}, args_t... next_args ) {
        struct data_t {
            first_t arg1;
            DWORD   syscall_id;
        } data{ arg, index };

        using call_stub_t = ret_t( __fastcall* )( data_t*, args_t... );
        return ( reinterpret_cast< call_stub_t >( &g_syscall_stub[ 0 ] ) )( &data, next_args... );
    }

    class c_driver {
    public:
        bool initialize( ) {
            m_driver_handle = ::CreateFileW(
                oxorany( L"\\\\.\\EBIoDispatch" ),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr );

            if ( !m_driver_handle || m_driver_handle == INVALID_HANDLE_VALUE ) {
                klog::print_error( oxorany( "[driver] CreateFileW on device object failed (gle=0x%x)" ), ::GetLastError( ) );
                return false;
            }

            klog::print_info( oxorany( "[driver] device bound -> handle=0x%p" ), m_driver_handle );
            return true;
        }

        void unload( ) {
            if ( m_driver_handle != INVALID_HANDLE_VALUE ) {
                ::CloseHandle( m_driver_handle );
                m_driver_handle = INVALID_HANDLE_VALUE;
            }
        }

        void close( ) {
            m_driver_handle = INVALID_HANDLE_VALUE;
        }

        HANDLE get_handle( ) const {
            return m_driver_handle;
        }

        void* map_physical_memory( uint64_t physical_address, uint32_t size ) {
            map_physical_input_t in{};
            in.m_physical_address = physical_address;
            in.m_size = size;

            std::uint32_t mapped_memory = 0;
            const auto status = send_cmd(
                k_ioctl_map,
                &in, sizeof( in ),
                &mapped_memory, sizeof( mapped_memory ) );

            if ( status )
                return nullptr;

            return resolve_mapped_address( mapped_memory );
        }

        void unmap_physical_memory( void* mapped_memory ) {
            unmap_physical_input_t in{};
            in.m_mapped_memory = reinterpret_cast< std::uint64_t >( mapped_memory );

            send_cmd( k_ioctl_unmap, &in, sizeof( in ), nullptr, 0 );
        }

        bool read_physical_memory( uint64_t pa, void* buffer, size_t size ) {
            if ( !util::is_physical_address_valid( pa, size ) )
                return false;

            auto* dst = static_cast< uint8_t* >( buffer );
            size_t offset = 0;

            while ( offset < size ) {
                const uint64_t cur_pa = pa + offset;
                const uint64_t page_base = cur_pa & k_page_mask;
                const uint32_t page_off = static_cast< uint32_t >( cur_pa & k_page_off_mask );
                const size_t   chunk = std::min< size_t >( size - offset, k_page_size - page_off );

                void* view = map_physical_memory( page_base, k_page_size );
                if ( view ) {
                    std::memcpy( dst + offset, static_cast< uint8_t* >( view ) + page_off, chunk );
                    unmap_physical_memory( view );
                }

                offset += chunk;
            }
            return true;
        }

        bool write_physical_memory( uint64_t pa, const void* buffer, size_t size ) {
            if ( !util::is_physical_address_valid( pa, size ) )
                return false;

            const auto* src = static_cast< const uint8_t* >( buffer );
            size_t      offset = 0;

            while ( offset < size ) {
                const uint64_t cur_pa = pa + offset;
                const uint64_t page_base = cur_pa & k_page_mask;
                const uint32_t page_off = static_cast< uint32_t >( cur_pa & k_page_off_mask );
                const size_t   chunk = std::min< size_t >( size - offset, k_page_size - page_off );

                void* view = map_physical_memory( page_base, k_page_size );
                if ( !view ) {
                    klog::print_error( oxorany( "[driver] physical mapping failed at pa=0x%llx (offset=0x%llx)" ), pa, offset );
                    return false;
                }

                std::memcpy( static_cast< uint8_t* >( view ) + page_off, src + offset, chunk );
                unmap_physical_memory( view );
                offset += chunk;
            }
            return true;
        }

    private:
        void* resolve_mapped_address( uint32_t truncated_address ) const {
            for ( uint64_t high = 0; high < k_resolve_hi_max; ++high ) {
                const uintptr_t test_addr =
                    ( high << 32 ) | static_cast< uint64_t >( truncated_address );

                MEMORY_BASIC_INFORMATION mbi{};
                if ( ::VirtualQuery( reinterpret_cast< void* >( test_addr ), &mbi, sizeof( mbi ) ) > 0 ) {
                    if ( mbi.State == MEM_COMMIT &&
                        reinterpret_cast< uintptr_t >( mbi.BaseAddress ) == test_addr ) {
                        return reinterpret_cast< void* >( test_addr );
                    }
                }
            }
            return nullptr;
        }

        NTSTATUS send_cmd(
            uint32_t ioctl_code,
            void* input_buffer,
            uint32_t input_size,
            void* output_buffer,
            uint32_t output_size ) const
        {
            if ( m_driver_handle == INVALID_HANDLE_VALUE ) {
                klog::print_error( oxorany( "[driver] send_cmd invoked without a valid device handle" ) );
                return STATUS_INVALID_HANDLE;
            }

            IO_STATUS_BLOCK block{};
            return driver::syscall< NTSTATUS >(
                k_syscall_index,
                m_driver_handle,
                nullptr,
                nullptr,
                nullptr,
                &block,
                ioctl_code,
                input_buffer,
                input_size,
                output_buffer,
                output_size );
        }

        HANDLE m_driver_handle = INVALID_HANDLE_VALUE;
    };

} // namespace driver

#endif // driver_driver_hpp