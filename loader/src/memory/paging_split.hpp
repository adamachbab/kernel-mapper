#ifndef paging_paging_split_hpp
#define paging_paging_split_hpp

namespace paging {

    inline void* c_paging::allocate_kernel_page() {
        return m_p_syscall->call_kernel<void*>(
            m_p_exports->m_mm_allocate_independent_pages_ex,
            reinterpret_cast<void*>( k_page_4kb_size ),
            reinterpret_cast<void*>( static_cast<std::uintptr_t>( -1 ) ), // node = MM_ANY_NODE_OK
            nullptr,
            nullptr );
    }

    inline std::uint64_t c_paging::get_physical_address( void* kernel_va ) {
        return m_p_syscall->call_kernel<std::uint64_t>(
            m_p_exports->m_mm_get_physical_address,
            kernel_va );
    }

    inline void c_paging::zero_kernel_page( void* kernel_va ) {
        // memset( dst, 0, 0x1000 )
        m_p_syscall->call_kernel<void*>(
            m_p_exports->m_memset,
            kernel_va,
            nullptr,
            reinterpret_cast<void*>( k_page_4kb_size ) );
    }

    inline void c_paging::flush_caches() {
        m_p_syscall->call_kernel<void*>( m_p_exports->m_ke_invalidate_all_caches );
    }

} // namespace paging

#endif // paging_paging_split_hpp