// bbport online module: shadPS4's memory manager as BBSC asks it (is this address mapped, with
// which protection), answered from the runtime's own map (runtime_memory_vma_info). Each thread
// remembers the last few mappings for a moment: BBSC checks every read it makes, and the map is
// behind a lock the game's own mappings take.
#pragma once
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/singleton.h"
#include "common/types.h"

extern "C" int runtime_memory_vma_info(uintptr_t address, int* prot, int* type, uintptr_t* end);

namespace Core {

enum class MemoryProt : u32 {
    NoAccess = 0,
    CpuRead = 1,
    CpuWrite = 2,
    CpuReadWrite = 3,
    CpuExec = 4,
    GpuRead = 16,
    GpuWrite = 32,
    GpuReadWrite = 48,
};

class MemoryManager {
public:
    bool IsValidMapping(u64 address, u64 size) {
        u32 prot = 0;
        void* start = nullptr;
        void* end = nullptr;
        return QueryProtection(address, &start, &end, &prot) == 0 &&
               address + size <= reinterpret_cast<u64>(end);
    }
    /// 0 and the mapping's range and protection (MemoryProt bits), or -1 when unmapped.
    int QueryProtection(u64 address, void** start, void** end, u32* prot) {
        struct Cached {
            u64 start = 0, end = 0;
            u32 prot = 0;
            std::chrono::steady_clock::time_point at{};
        };
        const auto now = std::chrono::steady_clock::now();
        if (address >= 0x0800000000ULL && address < 0x1000000000ULL) {
#ifdef _WIN32
            thread_local std::array<Cached, 16> low_cache{};
            thread_local unsigned low_next = 0;
            for (const auto& c : low_cache) {
                if (address >= c.start && address < c.end &&
                    now - c.at < std::chrono::milliseconds(2000)) {
                    *start = reinterpret_cast<void*>(c.start);
                    *end = reinterpret_cast<void*>(c.end);
                    *prot = c.prot;
                    return 0;
                }
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != 0 &&
                mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0) {
                u32 mp = 0;
                if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                    mp |= 1;
                }
                if (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) {
                    mp |= 3;
                }
                if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    mp |= 4;
                }
                if (mp != 0) {
                    auto& slot = low_cache[low_next++ % low_cache.size()];
                    slot = {reinterpret_cast<u64>(mbi.BaseAddress),
                            reinterpret_cast<u64>(mbi.BaseAddress) + mbi.RegionSize, mp, now};
                    *start = reinterpret_cast<void*>(slot.start);
                    *end = reinterpret_cast<void*>(slot.end);
                    *prot = slot.prot;
                    return 0;
                }
            }
            return -1;
#else
            struct LowRegion {
                u64 start = 0, end = 0;
                u32 prot = 0;
            };
            static std::vector<LowRegion> s_low_regions;
            static std::mutex s_low_mutex;
            static std::atomic<bool> s_low_init{false};

            if (!s_low_init.load(std::memory_order_acquire)) {
                std::lock_guard<std::mutex> lock(s_low_mutex);
                if (!s_low_init.load(std::memory_order_relaxed)) {
                    if (FILE* maps = std::fopen("/proc/self/maps", "r")) {
                        char line[512];
                        while (std::fgets(line, sizeof(line), maps)) {
                            unsigned long long m_start = 0, m_end = 0;
                            char perms[5] = {};
                            if (std::sscanf(line, "%llx-%llx %4s", &m_start, &m_end, perms) != 3) {
                                continue;
                            }
                            if (m_end <= 0x0800000000ULL) {
                                continue;
                            }
                            if (m_start >= 0x1000000000ULL) {
                                break;
                            }
                            const u32 mp = (perms[0] == 'r' ? 1u : 0u) |
                                           (perms[1] == 'w' ? 3u : 0u) |
                                           (perms[2] == 'x' ? 4u : 0u);
                            if (mp != 0) {
                                s_low_regions.push_back({u64(m_start), u64(m_end), mp});
                            }
                        }
                        std::fclose(maps);
                    }
                    s_low_init.store(true, std::memory_order_release);
                }
            }
            for (const auto& r : s_low_regions) {
                if (address >= r.start && address < r.end) {
                    *start = reinterpret_cast<void*>(r.start);
                    *end = reinterpret_cast<void*>(r.end);
                    *prot = r.prot;
                    return 0;
                }
            }
            return -1;
#endif
        }
        thread_local std::array<Cached, 8> cache{};
        thread_local unsigned next = 0;
        for (const auto& c : cache) {
            if (address >= c.start && address < c.end &&
                now - c.at < std::chrono::milliseconds(250)) {
                *start = reinterpret_cast<void*>(c.start);
                *end = reinterpret_cast<void*>(c.end);
                *prot = c.prot;
                return 0;
            }
        }
        int p = 0, type = -1;
        uintptr_t mapping_end = 0;
        if (!runtime_memory_vma_info(address, &p, &type, &mapping_end)) {
            return -1;
        }
        // The runtime's map gives the end of the mapping, not its start: the address itself
        // stands for it (callers check address >= start).
        auto& slot = cache[next++ % cache.size()];
        const u32 mp = u32(p) | ((p & 2) ? 1u : 0u);
        slot = {address & ~u64(0xfff), mapping_end, mp, now};
        *start = reinterpret_cast<void*>(slot.start);
        *end = reinterpret_cast<void*>(slot.end);
        *prot = slot.prot;
        return 0;
    }
};

using Memory = Common::Singleton<MemoryManager>;

} // namespace Core
