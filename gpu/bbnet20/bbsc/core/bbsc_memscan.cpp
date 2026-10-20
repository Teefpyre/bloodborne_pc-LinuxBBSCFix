// SPDX-FileCopyrightText: Copyright 2026 CLS_AMG
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/bbsc_memscan.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#ifndef _WIN32
#include <cerrno>
#include <sys/uio.h>
#include <unistd.h>

extern "C" int runtime_memory_region(std::uintptr_t address, std::uintptr_t* start,
                                     std::uintptr_t* end, int* mapped);
extern "C" void runtime_memory_read_backing(std::uintptr_t address, void* data,
                                            std::uint64_t size);
#endif

namespace Core::Bbsc {

namespace {

#ifdef _WIN32
// One region. The emulator changes page protection all the time (GPU tracking), so a page that was
// readable a moment ago may fault now: the search runs under SEH and a fault just ends the region.
void SearchRegion(const std::uint8_t* start, std::size_t size, const std::uint8_t* needle,
                  std::size_t length, std::vector<std::uint64_t>& hits, std::size_t max_hits) {
    __try {
        const std::uint8_t* end = start + size;
        const std::uint8_t* at = start;
        while (hits.size() < max_hits && end - at >= static_cast<std::ptrdiff_t>(length)) {
            at = static_cast<const std::uint8_t*>(
                std::memchr(at, needle[0], static_cast<std::size_t>(end - at) - length + 1));
            if (at == nullptr) {
                break;
            }
            if (std::memcmp(at, needle, length) == 0) {
                hits.push_back(reinterpret_cast<std::uint64_t>(at));
            }
            ++at;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
#endif

} // namespace

std::vector<std::uint64_t> FindInMemory(std::span<const std::uint8_t> needle, std::uint64_t lo,
                                        std::uint64_t hi, std::size_t max_hits) {
    std::vector<std::uint64_t> hits;
#ifdef _WIN32
    if (needle.empty()) {
        return hits;
    }
    constexpr DWORD Readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    std::uint64_t at = lo;
    while (at < hi && hits.size() < max_hits) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<void*>(at), &info, sizeof(info)) == 0) {
            break;
        }
        const auto start = reinterpret_cast<std::uint64_t>(info.BaseAddress);
        const std::uint64_t end = start + info.RegionSize;
        if (info.State == MEM_COMMIT && (info.Protect & Readable) != 0 &&
            (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            SearchRegion(reinterpret_cast<const std::uint8_t*>(start), info.RegionSize,
                         needle.data(), needle.size(), hits, max_hits);
        }
        if (end <= at) {
            break;
        }
        at = end;
    }
#else
    if (needle.empty() || lo >= hi) {
        return hits;
    }
    constexpr std::size_t Piece = 1u << 20;
    std::vector<std::uint8_t> buffer(Piece + needle.size());
    constexpr std::uint64_t GuestMin = 0x1000000000ULL;
    auto match_chunk = [&](std::uint64_t base, std::size_t len) {
        const std::uint8_t* data = buffer.data();
        const std::uint8_t* last = data + len - needle.size();
        for (const std::uint8_t* p = data; p <= last && hits.size() < max_hits; ++p) {
            p = static_cast<const std::uint8_t*>(
                std::memchr(p, needle[0], std::size_t(last - p) + 1));
            if (!p) {
                break;
            }
            if (std::size_t(p - data) < Piece &&
                std::memcmp(p, needle.data(), needle.size()) == 0) {
                hits.push_back(base + std::uint64_t(p - data));
            }
        }
    };

    // Low mappings below GuestMin (the eboot image): readable mappings from /proc/self/maps.
    if (lo < GuestMin) {
        const std::uint64_t low_hi = std::min<std::uint64_t>(hi, GuestMin);
        if (FILE* maps = std::fopen("/proc/self/maps", "r")) {
            char line[512];
            while (hits.size() < max_hits && std::fgets(line, sizeof(line), maps)) {
                unsigned long long start = 0, end = 0;
                char perms[5] = {};
                if (std::sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3 ||
                    perms[0] != 'r') {
                    continue;
                }
                start = std::max<unsigned long long>(start, lo);
                end = std::min<unsigned long long>(end, low_hi);
                for (std::uint64_t at = start; at < end && hits.size() < max_hits; at += Piece) {
                    const std::size_t want =
                        std::size_t(std::min<std::uint64_t>(end - at, Piece + needle.size() - 1));
                    iovec local{buffer.data(), want};
                    iovec remote{reinterpret_cast<void*>(at), want};
                    ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
                    if (got < ssize_t(needle.size())) {
                        if (errno == EPERM || errno == ENOSYS) {
                            std::memcpy(buffer.data(), reinterpret_cast<const void*>(at), want);
                            got = ssize_t(want);
                        } else {
                            continue;
                        }
                    }
                    match_chunk(at, got);
                }
            }
            std::fclose(maps);
        }
    }
    // Guest direct/flexible memory from GuestMin up: read through the runtime's backing view so
    // GPU read/write page traps never split or block a region.
    for (std::uint64_t at = std::max<std::uint64_t>(lo, GuestMin);
         at < hi && hits.size() < max_hits;) {
        std::uintptr_t r_start = 0, r_end = 0;
        int mapped = 0;
        if (!runtime_memory_region(at, &r_start, &r_end, &mapped) || r_end <= at) {
            break;
        }
        if (!mapped) {
            at = r_end;
            continue;
        }
        const std::uint64_t start = std::max<std::uint64_t>(r_start, at);
        const std::uint64_t end = std::min<std::uint64_t>(r_end, hi);
        for (std::uint64_t chunk = start; chunk < end && hits.size() < max_hits; chunk += Piece) {
            const std::size_t want =
                std::size_t(std::min<std::uint64_t>(end - chunk, Piece + needle.size() - 1));
            if (want < needle.size()) {
                break;
            }
            runtime_memory_read_backing(chunk, buffer.data(), want);
            match_chunk(chunk, want);
        }
        at = r_end;
    }
#endif
    return hits;
}

} // namespace Core::Bbsc
