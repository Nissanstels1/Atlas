"""Bounded node checks; only the caller writes shared state."""
from pathlib import Path
import time


def probe_workers(meminfo=Path('/proc/meminfo')):
    """Allow two engines only with at least 256 MiB available RAM."""
    try:
        for line in meminfo.read_text().splitlines():
            if line.startswith('MemAvailable:'):
                return 2 if int(line.split()[1]) >= 256 * 1024 else 1
    except (OSError, ValueError, IndexError):
        pass
    return 1


def probe_batch(nodes, check, workers=1):
    """Yield completed results, without queueing thousands of engine launches.

    A failed check never aborts the remaining nodes. Exception text may contain
    credentials, so unexpected exceptions are deliberately not exposed.
    """
    def safe_check(node):
        try:
            return check(node)
        except Exception:
            return {'ok': False, 'stage': 'engine', 'checked': int(time.time()),
                    'error': 'Не удалось выполнить проверку узла'}

    workers = max(1, min(2, int(workers)))
    if workers == 1:
        for node in nodes:
            yield node, safe_check(node)
        return
    # Some minimal Python installations omit concurrent.futures. Remain usable
    # there without adding a mandatory package dependency.
    try:
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
    except ImportError:
        yield from probe_batch(nodes, check, workers=1)
        return
    iterator = iter(nodes)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}
        for _ in range(workers):
            node = next(iterator, None)
            if node is not None:
                pending[pool.submit(safe_check, node)] = node
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                node = pending.pop(future)
                yield node, future.result()
                following = next(iterator, None)
                if following is not None:
                    pending[pool.submit(safe_check, following)] = following
