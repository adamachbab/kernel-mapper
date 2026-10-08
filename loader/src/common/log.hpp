#ifndef log_hpp
#define log_hpp

namespace klog {

    enum class level { trace, debug, info, warn, error, fatal, off };

    namespace detail {

        inline level& min_level( ) {
#ifdef _DEBUG
            static level lvl = level::debug;
#else
            static level lvl = level::info;
#endif
            return lvl;
        }

        inline std::mutex& io_mutex( ) {
            static std::mutex m;
            return m;
        }

        inline const char* tag( level lvl ) noexcept {
            switch ( lvl ) {
            case level::trace: return "trace";
            case level::debug: return "debug";
            case level::info:  return "info";
            case level::warn:  return "warn";
            case level::error: return "error";
            case level::fatal: return "fatal";
            default:           return "?";
            }
        }

        inline void print_timestamp( ) {
            auto now = std::chrono::system_clock::now( );
            std::time_t time = std::chrono::system_clock::to_time_t( now );

            std::tm tm{};
#if defined(_WIN32)
            localtime_s( &tm, &time );
#else
            localtime_r( &time, &tm );
#endif

            std::printf(
                "\x1b[38;2;120;170;190m["
                "\x1b[38;2;115;165;187m%02d"
                "\x1b[38;2;110;160;184m/"
                "\x1b[38;2;105;155;181m%02d"
                "\x1b[38;2;100;150;178m/"
                "\x1b[38;2;95;145;175m%04d"
                "\x1b[38;2;90;140;172m "
                "\x1b[38;2;85;135;169m%02d"
                "\x1b[38;2;80;130;166m:"
                "\x1b[38;2;75;125;163m%02d"
                "\x1b[38;2;72;118;161m:"
                "\x1b[38;2;70;110;160m%02d]\x1b[0m ",
                tm.tm_mon + 1, tm.tm_mday, tm.tm_year + 1900,
                tm.tm_hour, tm.tm_min, tm.tm_sec );
        }

        inline void print_prefix( level lvl ) {
            print_timestamp( );
            std::printf( "\x1b[38;2;210;210;210m[%s] ", tag( lvl ) );
        }

        inline bool enable_vt( ) noexcept {
#if defined(_WIN32)
            auto on = [ ] ( DWORD id ) {
                HANDLE h = ::GetStdHandle( id );
                DWORD  mode = 0;
                if ( h == INVALID_HANDLE_VALUE || !h )     return false;
                if ( !::GetConsoleMode( h, &mode ) )       return false;
                return ::SetConsoleMode( h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING ) != FALSE;
                };
            return on( STD_OUTPUT_HANDLE ) && on( STD_ERROR_HANDLE );
#else
            return true;
#endif
        }

        inline bool force_raster_font( ) noexcept {
#if defined(_WIN32)
            HANDLE h = ::GetStdHandle( STD_OUTPUT_HANDLE );
            if ( h == INVALID_HANDLE_VALUE || !h )
                return false;

            CONSOLE_FONT_INFOEX cfi{ };
            cfi.cbSize       = sizeof( cfi );
            cfi.nFont        = 0;
            cfi.dwFontSize.X = 8;
            cfi.dwFontSize.Y = 12;
            cfi.FontFamily   = FF_DONTCARE | RASTER_FONTTYPE;
            cfi.FontWeight   = FW_NORMAL;
            wcscpy_s( cfi.FaceName, L"Terminal" );
            return ::SetCurrentConsoleFontEx( h, FALSE, &cfi ) != FALSE;
#else
            return true;
#endif
        }

        inline bool resize_console( ) noexcept {
#if defined(_WIN32)
            HANDLE h = ::GetStdHandle( STD_OUTPUT_HANDLE );
            if ( h == INVALID_HANDLE_VALUE || !h )
                return false;

            const SHORT cols = 140;
            const SHORT rows = 40;

            SMALL_RECT shrink = { 0, 0, 1, 1 };
            ::SetConsoleWindowInfo( h, TRUE, &shrink );

            COORD buffer = { cols, 9000 };
            if ( !::SetConsoleScreenBufferSize( h, buffer ) )
                return false;

            SMALL_RECT window = { 0, 0, static_cast< SHORT >( cols - 1 ),
                                         static_cast< SHORT >( rows - 1 ) };
            return ::SetConsoleWindowInfo( h, TRUE, &window ) != FALSE;
#else
            return true;
#endif
        }

        inline const bool g_auto_resize = resize_console( );
        inline const bool g_auto_init = enable_vt( );
        inline const bool g_auto_font = force_raster_font( );

    } // namespace detail

    inline void  set_min_level( level lvl ) noexcept { detail::min_level( ) = lvl; }
    inline level get_min_level( )            noexcept { return detail::min_level( ); }

    template <typename... args_t>
    inline void print( level lvl, const char* format, args_t... args ) {
        if ( static_cast< int >( lvl ) < static_cast< int >( detail::min_level( ) ) )
            return;

        std::lock_guard<std::mutex> lk( detail::io_mutex( ) );
        detail::print_prefix( lvl );
        std::printf( format, args... );
        std::printf( "\x1b[0m\n" );
        std::fflush( stdout );
    }

    template <typename... args_t>
    inline void print_section( level lvl, const char* format, args_t... args ) {
        if ( static_cast< int >( lvl ) < static_cast< int >( detail::min_level( ) ) )
            return;

        std::lock_guard<std::mutex> lk( detail::io_mutex( ) );
        std::printf( "\n" );
        detail::print_prefix( lvl );
        std::printf( format, args... );
        std::printf( "\x1b[0m\n" );
        std::fflush( stdout );
    }

    template <typename... args_t>
    inline void print( const char* format, args_t... args ) {
        std::lock_guard<std::mutex> lk( detail::io_mutex( ) );
        detail::print_timestamp( );
        std::printf( "\x1b[38;2;210;210;210m" );
        std::printf( format, args... );
        std::printf( "\x1b[0m\n" );
        std::fflush( stdout );
    }

    template <typename... args_t> inline void print_trace( const char* f, args_t... a ) { print( level::trace, f, a... ); }
    template <typename... args_t> inline void print_debug( const char* f, args_t... a ) { print( level::debug, f, a... ); }
    template <typename... args_t> inline void print_info( const char* f, args_t... a ) { print( level::info, f, a... ); }
    template <typename... args_t> inline void print_warn( const char* f, args_t... a ) { print( level::warn, f, a... ); }
    template <typename... args_t> inline void print_error( const char* f, args_t... a ) { print( level::error, f, a... ); }
    template <typename... args_t> inline void print_fatal( const char* f, args_t... a ) { print( level::fatal, f, a... ); }

    template <typename... args_t> inline void print_stage( const char* f, args_t... a ) { print_section( level::info, f, a... ); }

} // namespace klog

#endif // log_hpp