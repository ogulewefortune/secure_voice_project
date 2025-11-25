#!/usr/bin/env python3
"""
Security Test Runner
Runs comprehensive security tests for eavesdropping, imposter clients, and MITM scenarios.
"""

import sys
import time
import unittest
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tests.test_security_attacks import (
    TestEavesdropping,
    TestImposterClient,
    TestManInTheMiddle,
    TestIntegrityProtection
)


def run_security_tests():
    """Run all security tests."""
    print("=" * 80)
    print("SECURITY TEST SUITE")
    print("Testing: Eavesdropping, Imposter Clients, Man-in-the-Middle Attacks")
    print("=" * 80)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEavesdropping))
    suite.addTests(loader.loadTestsFromTestCase(TestImposterClient))
    suite.addTests(loader.loadTestsFromTestCase(TestManInTheMiddle))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrityProtection))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print()
    
    if result.failures:
        print("FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}")
            print(f"    {traceback[:200]}...")
        print()
    
    if result.errors:
        print("ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}")
            print(f"    {traceback[:200]}...")
        print()
    
    if result.wasSuccessful():
        print("✅ All security tests PASSED!")
        print("The system is protected against:")
        print("  - Eavesdropping attacks")
        print("  - Imposter client attacks")
        print("  - Man-in-the-middle attacks")
        print("  - Message tampering")
        return 0
    else:
        print("❌ Some security tests FAILED!")
        print("Review the failures above.")
        return 1


if __name__ == "__main__":
    exit_code = run_security_tests()
    sys.exit(exit_code)

