#!/usr/bin/env python3
"""Run backend logic tests on Windows; Linux-only tests remain explicitly skipped.

This runner does not validate procd, firewall, TUN or Linux flock semantics.
It provides a real Windows file lock only for test fixtures that use locked().
"""
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if os.name == 'nt':
    import msvcrt
    def flock(file, flags):
        position = file.tell()
        file.seek(0)
        operation = msvcrt.LK_UNLCK if flags & 8 else msvcrt.LK_NBLCK if flags & 4 else msvcrt.LK_LOCK
        try:
            try:
                msvcrt.locking(file.fileno(), operation, 1)
            except PermissionError as exc:
                raise BlockingIOError(str(exc)) from exc
        finally:
            file.seek(position)
    sys.modules['fcntl'] = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, flock=flock)

sys.path.insert(0, str(ROOT / 'tests'))
suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
def cases(value):
    for item in value:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item
if os.name == 'nt':
    import atlas
    for item in cases(suite):
        if item._testMethodName in ('test_atomic_permissions', 'test_controller_secret_persistent_private_and_not_in_status'):
            setattr(type(item), item._testMethodName, unittest.skip('POSIX filesystem permissions require Linux')(getattr(type(item), item._testMethodName)))
    print('Windows host logic tests: Linux cache-directory creation is mocked; POSIX permission tests skipped.')
    with mock.patch.object(atlas, 'prepare_runtime_paths'):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
else:
    result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
