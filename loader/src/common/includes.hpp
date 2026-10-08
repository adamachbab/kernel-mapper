#ifndef common_includes_hpp
#define common_includes_hpp

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <utility>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <mutex>
#include <shared_mutex>
#include <type_traits>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <urlmon.h>

#include <atlbase.h>
#include <dia2.h>
#include <diacreate.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "diaguids.lib")

#include "oxorany/include.hpp"

#include "common/log.hpp"
#include "common/types.hpp"
#include "symbols/pdb.hpp"
#include "driver/bytes.hpp"
#include "driver/driver.hpp"
#include "driver/service.hpp"
#include "symbols/exports.hpp"
#include "memory/paging.hpp"
#include "memory/syscall.hpp"
#include "memory/paging_split.hpp"
#include "memory/syscall.hpp"
#include "memory/map/dependency.hpp"
#include "memory/map/allocator.hpp"
#include "memory/map/entry.hpp"
#include "memory/map/map.hpp"

#endif // common_includes_hpp