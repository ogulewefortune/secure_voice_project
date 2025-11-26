#!/usr/bin/env python3
"""
Security Demonstration Script
Shows project implementation overview and demonstrates security features.
"""

import sys
import subprocess
from pathlib import Path

def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def print_section(text):
    """Print a formatted section."""
    print(f"\n{'-' * 80}")
    print(f"  {text}")
    print(f"{'-' * 80}\n")

def main():
    """Main demonstration function."""
    print_header("SECURE VOICE COMMUNICATION - SECURITY DEMONSTRATION")
    
    print("This demonstration shows the security features of the Secure Voice Communication system.")
    print("\nThe system protects against:")
    print("  - Eavesdropping attacks")
    print("  - Imposter client attacks")
    print("  - Man-in-the-middle attacks")
    print("  - Message tampering")
    
    print_section("Security Features")
    
    print("1. AES-256-GCM Encryption")
    print("   - Provides confidentiality")
    print("   - Prevents unauthorized decryption")
    print("   - Includes authentication tags for integrity")
    
    print("\n2. ECDH Key Exchange")
    print("   - Secure key derivation")
    print("   - Requires private keys from both parties")
    print("   - Prevents imposter clients")
    
    print("\n3. HMAC-SHA256 Integrity Checks")
    print("   - Detects message tampering")
    print("   - Verifies data authenticity")
    
    print("\n4. Intrusion Detection System (IDS)")
    print("   - Real-time threat detection")
    print("   - Automatic alert generation")
    print("   - Web interface integration")
    
    print_section("Audio Quality Requirements")
    
    print("The system meets the following requirements:")
    print("  - Quantization SNR: >= 40dB")
    print("  - Link Capacity: 64 Kbps")
    print("  - Protection: Eavesdropping, Imposter Clients, Content Manipulation")
    
    print_section("Running Security Tests")
    
    response = input("Would you like to run the security tests? (y/n): ").strip().lower()
    
    if response == 'y':
        print("\nRunning automated security tests...\n")
        try:
            result = subprocess.run(
                [sys.executable, "tests/run_security_tests.py"],
                cwd=Path(__file__).parent,
                check=False
            )
            if result.returncode == 0:
                print("\n[PASSED] All security tests passed!")
            else:
                print("\n[FAILED] Some tests failed. Check the output above for details.")
        except Exception as e:
            print(f"\nError running tests: {e}")
    else:
        print("\nSkipping automated tests.")
        print("You can run them manually with:")
        print("  python3 tests/run_security_tests.py")
    
    print_section("Interactive Demonstrations")
    
    response = input("Would you like to see interactive security demonstrations? (y/n): ").strip().lower()
    
    if response == 'y':
        print("\nRunning interactive demonstrations...\n")
        try:
            subprocess.run(
                [sys.executable, "tests/security_test_manual.py"],
                cwd=Path(__file__).parent,
                check=False
            )
        except Exception as e:
            print(f"\nError running demonstrations: {e}")
    else:
        print("\nSkipping interactive demonstrations.")
        print("You can run them manually with:")
        print("  python3 tests/security_test_manual.py")
    
    print_section("Web Interface")
    
    print("To see security alerts in real-time:")
    print("  1. Start the voice server: python3 run_server.py")
    print("  2. Start the web server: python3 run_web_server.py")
    print("  3. Open http://localhost:5000 in your browser")
    print("  4. Connect to the server and perform attacks")
    print("  5. Watch the Security Alerts panel for real-time threat detection")
    
    print_section("Test in Browser Console")
    
    print("To test the alert system in the web interface:")
    print("  1. Open the browser console (F12)")
    print("  2. Type: testSecurityAlert()")
    print("  3. You should see a test alert appear in the UI")
    
    print_header("Demonstration Complete")
    
    print("For more information, see:")
    print("  - docs/SECURITY_TESTS.md - Detailed test documentation")
    print("  - docs/INTRUSION_DETECTION.md - IDS documentation")
    print("  - docs/technical_documentation.md - Technical details")

if __name__ == "__main__":
    main()

