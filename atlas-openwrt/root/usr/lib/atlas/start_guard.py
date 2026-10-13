"""Supervise one engine generation; never hand LAN DNS to an unready child."""
import time


def clock_ready(now, last_ready=0):
    minimum=max(last_ready if type(last_ready) is int else 0,1672531200)
    return now+300 >= minimum


def supervise(child, ready, attach, restore, report, stopped=lambda: False,
              clock=time.monotonic, sleep=time.sleep, start_timeout=45,
              interval=5, failure_limit=3):
    start = clock()
    attached = False
    failures = 0
    stage = 'starting'
    report(stage, local_ready=False)
    try:
        while not stopped():
            if child.poll() is not None:
                stage = 'engine-exited'
                return 1
            try:
                available = ready()
            except Exception:
                available = False
            if available:
                if stopped():
                    stage='stopped'
                    return 0
                failures = 0
                if not attached:
                    stage = 'connecting-dns'
                    report(stage, local_ready=True)
                    attach()
                    attached = True
                    if stopped():
                        stage='stopped'
                        return 0
                    stage = 'ready'
                    report(stage, local_ready=True, internet_verified=False)
            elif not attached:
                if clock() - start >= start_timeout:
                    stage = 'ready-timeout'
                    return 1
            else:
                failures += 1
                if failures >= failure_limit:
                    stage = 'engine-unresponsive'
                    return 1
            sleep(interval if attached else .5)
        stage = 'stopped'
        return 0
    except Exception:
        # No exception messages here: they can contain proxy credentials/URLs.
        stage = 'dns-integration-failed' if stage == 'connecting-dns' else 'supervisor-failed'
        return 1
    finally:
        # Terminate first, so a second generation cannot race with restoration.
        if child.poll() is None:
            try:
                child.terminate()
                child.wait(timeout=5)
            except Exception:
                try:
                    child.kill()
                    child.wait(timeout=5)
                except Exception:
                    pass
        restored = False
        try:
            restored = restore() is not False
        except Exception:
            pass
        report(stage, local_ready=False, network_restored=restored,
               failed=stage != 'stopped')
