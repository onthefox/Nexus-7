#!/usr/bin/env python3
"""
Nexus-7 Test Runner

Standalone test runner that doesn't require pytest.
Runs all test suites and reports results.

Usage:
    python run_tests.py [--verbose]
"""

import sys
import os
import traceback
from typing import List, Tuple


class TestResult:
    """Simple test result container."""
    def __init__(self, name: str, passed: bool, error: str = None):
        self.name = name
        self.passed = passed
        self.error = error


def run_test(test_name: str, test_func) -> TestResult:
    """Run a single test function and return result."""
    try:
        test_func()
        return TestResult(test_name, True)
    except Exception as e:
        return TestResult(test_name, False, str(e))


def run_test_class(test_class) -> List[TestResult]:
    """Run all test methods in a test class."""
    results = []
    class_name = test_class.__name__
    
    # Get all test methods
    test_methods = [m for m in dir(test_class) if m.startswith('test_')]
    
    for method_name in test_methods:
        full_name = f"{class_name}.{method_name}"
        instance = test_class()
        method = getattr(instance, method_name)
        results.append(run_test(full_name, method))
    
    return results


def main():
    """Main test runner."""
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    
    print("=" * 70)
    print("Nexus-7 CTF-OS Ecosystem - Test Suite")
    print("=" * 70)
    print()
    
    all_results = []
    
    # Import and run test classes from test_all.py
    print("Loading test modules...")
    from tests.test_all import (
        TestSymbioCTF,
        TestNexusOrchestrator,
        TestGauntlet,
        TestEfficiency,
        TestAlignment,
        TestLedger,
    )
    
    test_classes = [
        TestSymbioCTF,
        TestNexusOrchestrator,
        TestGauntlet,
        TestEfficiency,
        TestAlignment,
        TestLedger,
    ]
    
    print(f"Found {len(test_classes)} test classes")
    print()
    
    # Run all test classes
    for test_class in test_classes:
        print(f"Running {test_class.__name__}...")
        results = run_test_class(test_class)
        all_results.extend(results)
        
        for result in results:
            status = "✓ PASS" if result.passed else "✗ FAIL"
            if verbose or not result.passed:
                print(f"  {status}: {result.name}")
                if not result.passed:
                    print(f"    Error: {result.error}")
    
    print()
    print("=" * 70)
    
    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r.passed)
    failed = total - passed
    
    print(f"Results: {passed}/{total} tests passed")
    
    if failed > 0:
        print(f"\nFailed tests:")
        for result in all_results:
            if not result.passed:
                print(f"  - {result.name}")
                if verbose:
                    print(f"    {result.error}")
        print()
        print("=" * 70)
        sys.exit(1)
    else:
        print("\nAll tests passed! ✓")
        print("=" * 70)
        sys.exit(0)


if __name__ == '__main__':
    main()
