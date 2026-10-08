#include "common/includes.hpp"

int main( int argc, char* argv[ ] ) {
    klog::print_info( oxorany( "[boot] loader entry reached, argc=%d" ), argc );

    if ( argc < 2 ) {
        klog::print_error( oxorany( "[boot] missing payload argument -> expected: loader.exe <driver.sys>" ) );
        std::getchar( );
        return 1;
    }

    klog::print_info( oxorany( "[boot] target payload -> %s" ), argv[ 1 ] );

    pdb::c_pdb ntos( oxorany( "ntoskrnl.exe" ) );
    klog::print_stage( oxorany( "[pdb] requesting ntoskrnl symbols from microsoft servers..." ) );
    if ( !ntos.load( ) ) {
        klog::print_error( oxorany( "[pdb] ntoskrnl PDB acquisition aborted" ) );
        std::getchar( );
        return 1;
    }
    klog::print_info( oxorany( "[pdb] parsed %zu symbols from %s" ),
        ntos.m_symbols.size( ), ntos.m_module_bare.c_str( ) );

    service::c_service svc;
    klog::print_stage( oxorany( "[service] spawning kernel service entry..." ) );
    if ( !svc.create( ) ) {
        klog::print_error( oxorany( "[service] service registration refused by kernel" ) );
        std::getchar( );
        return 1;
    }
    klog::print_info( oxorany( "[service] active -> %ls" ), svc.driver_name( ) );

    driver::c_driver drv;
    klog::print_stage( oxorany( "[driver] acquiring device handle..." ) );
    if ( !drv.initialize( ) ) {
        klog::print_error( oxorany( "[driver] device channel unavailable" ) );
        svc.unload( );
        std::getchar( );
        return 1;
    }
    klog::print_info( oxorany( "[driver] channel open -> handle=0x%p" ), drv.get_handle( ) );

    paging::c_paging pg( drv );
    klog::print_stage( oxorany( "[paging] walking physical memory to locate system DTB..." ) );
    if ( !pg.setup( ) ) {
        klog::print_error( oxorany( "[paging] DTB discovery failed, aborting" ) );
        drv.unload( );
        svc.unload( );
        std::getchar( );
        return 1;
    }

    syscall::c_syscall sc( drv, pg, ntos );
    klog::print_stage( oxorany( "[syscall] preparing SSDT hijack bridge..." ) );
    if ( !sc.setup( ) ) {
        klog::print_error( oxorany( "[syscall] SSDT bridge setup aborted" ) );
        drv.unload( );
        svc.unload( );
        std::getchar( );
        return 1;
    }

    exports::c_exports exp( ntos );
    klog::print_stage( oxorany( "[exports] resolving required kernel routines..." ) );
    if ( !exp.setup( ) ) {
        klog::print_error( oxorany( "[exports] one or more kernel routines missing" ) );
        drv.unload( );
        svc.unload( );
        std::getchar( );
        return 1;
    }

    pg.attach_syscall( sc );
    pg.attach_exports( exp );
    klog::print_info( oxorany( "[paging] syscall + exports bound to paging engine" ) );

    map::c_allocator alloc( drv, pg, ntos );

    auto dependency = std::make_shared< map::c_dependency >( argv[ 1 ] );
    klog::print_stage( oxorany( "[dependency] loading payload image from disk..." ) );
    if ( !dependency->load( ) ) {
        klog::print_error( oxorany( "[dependency] payload image rejected" ) );
        drv.unload( );
        svc.unload( );
        std::getchar( );
        return 1;
    }
    klog::print_info( oxorany( "[dependency] payload loaded (image size=0x%x, sections=%u)" ),
        dependency->get_size( ), dependency->get_section_count( ) );

    auto mapper = std::make_unique< map::c_map >( drv, pg, sc, ntos, exp, alloc, dependency );
    klog::print_stage( oxorany( "[map] beginning manual map stage..." ) );
    if ( !mapper->create( ) ) {
        klog::print_error( oxorany( "[map] manual map stage failed" ) );
        drv.unload( );
        svc.unload( );
        std::getchar( );
        return 1;
    }

    klog::print_stage( oxorany( "[map] handing control to kernel entry point..." ) );
    if ( !mapper->execute( ) )
        klog::print_error( oxorany( "[map] kernel entry point reported failure" ) );

    klog::print_stage( oxorany( "[shutdown] tearing down driver + service..." ) );
    drv.unload( );
    svc.cleanup( );
    svc.unload( );

    klog::print_info( oxorany( "[shutdown] loader exited gracefully" ) );
    std::getchar( );
    return 0;
}