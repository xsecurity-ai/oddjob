"""Giving freed memory back to the operating system.

CPython frees a Python object to its own allocator, which frees to
glibc, which mostly does not free to the kernel. A process that
allocates 400 MB in a burst and drops it keeps the 400 MB resident:
RSS is a high-water mark, not a measure of what is in use.

That is normally harmless and here it was not. The asset worker runs a
cycle a minute and each one allocates and discards a large working
set, so the mark climbed to whatever the worst cycle needed and stayed
there -- on the live instance 3.0 GB, flat, with nothing leaking. An
operator reading `docker stats` sees a leak, the container sits near
its limit for no reason, and the next genuinely large import meets a
ceiling that is mostly free space.

Two things help and neither costs anything in quality or speed:

  MALLOC_ARENA_MAX   glibc gives each thread its own arena, up to
                     8 x cores -- 144 on an 18-core host -- and every
                     arena fragments on its own. Capping it is a
                     compose-file environment variable; see
                     docker-compose.yml. Contention only matters for
                     heavily multithreaded malloc, and this process is
                     one asyncio loop with a small threadpool.

  malloc_trim        asks glibc to return the free top of the heap.
                     Milliseconds, and called where the churn is
                     rather than on a timer.

**Deliberately not called per request.** Trimming costs a walk of the
free lists, and doing it on a hot path to save memory nobody needed
would be trading the thing we have for the thing we do not.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os

log = logging.getLogger("oddjob.heap")

#: Only worth saying out loud when it actually moved something.
_NOTABLE_MB = 64


def rss_mb() -> float:
    """Resident set in MB, or 0.0 where it cannot be read.

    From /proc because `resource.getrusage` reports the PEAK, which is
    the number this module exists to bring down and therefore the one
    that cannot measure it.
    """
    try:
        with open("/proc/self/statm") as fh:
            pages = int(fh.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / 2**20
    except (OSError, ValueError, IndexError):
        return 0.0


def trim() -> float:
    """Return the free top of the heap to the OS. -> MB released.

    Best effort in every direction: musl has no `malloc_trim`, a
    non-Linux host has no `/proc/self/statm`, and neither is a reason
    for a background worker to fail. 0.0 means "nothing measurable",
    which includes "could not measure".
    """
    before = rss_mb()
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        libc.malloc_trim(ctypes.c_size_t(0))
    except (OSError, AttributeError):
        # musl, or a libc without it. Said once at debug and never
        # again -- a warning every minute about a platform difference
        # is noise that trains people to ignore the log.
        log.debug("malloc_trim is not available on this libc")
        return 0.0
    freed = before - rss_mb()
    if freed >= _NOTABLE_MB:
        log.info("returned %.0f MB to the OS (rss %.0f -> %.0f MB)",
                 freed, before, before - freed)
    return max(freed, 0.0)
