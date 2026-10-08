#include <ntifs.h>

typedef struct _entry_pdb_t {
    unsigned __int64 m_dbg_print_ex;        // +0x00
} entry_pdb_t;

typedef struct _map_entry_t {
    entry_pdb_t      m_pdb;                 // +0x00
    unsigned __int64 m_directory_table_base;// +0x08
    unsigned __int64 m_ntoskrnl_base;       // +0x10
    unsigned __int64 m_image_size;          // +0x18
    unsigned __int64 m_image_base;          // +0x20
} map_entry_t;

typedef ULONG ( __cdecl* dbg_print_ex_t )(
    ULONG component_id,
    ULONG level,
    PCSTR format,
    ...
);

bool entry( map_entry_t* entry_data ) {
    if ( !entry_data )
        return false;

    const auto dbg_print_ex =
        reinterpret_cast< dbg_print_ex_t >( entry_data->m_pdb.m_dbg_print_ex );

    if ( !dbg_print_ex )
        return false;

    dbg_print_ex(
        0, 0,
        "[workspace] hello world from mapped driver!\n"
        "[workspace]   image_base = 0x%llx\n"
        "[workspace]   image_size = 0x%llx\n"
        "[workspace]   ntoskrnl   = 0x%llx\n"
        "[workspace]   system_cr3 = 0x%llx\n",
        entry_data->m_image_base,
        entry_data->m_image_size,
        entry_data->m_ntoskrnl_base,
        entry_data->m_directory_table_base );

    return true;
}