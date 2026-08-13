"""Subprocess coverage instrumentation hook for pytest-cov.

Automatically starts coverage measurement in forked subprocesses when
COVERAGE_PROCESS_START is set in the environment.
"""
import coverage

coverage.process_startup()
