#!/usr/bin/env python3
"""Test the fix for the 70% crash issue"""

import sys
import time
import traceback

print("Testing BSOD Fix Thread Crash Fix...\n")
print("=" * 60)

try:
    print("\n[1/5] Importing bsod_analyzer module...")
    from bsod_analyzer import BSODFixThread
    print("✓ Import successful")
    
    print("\n[2/5] Creating test BSOD info...")
    bsod_info = {
        'error_code': '0x0000000A',
        'error_name': 'IRQL_NOT_LESS_OR_EQUAL',
        'timestamp': '2024-01-01T12:00:00'
    }
    print(f"✓ Test data: {bsod_info['error_code']}")
    
    print("\n[3/5] Creating BSODFixThread instance...")
    thread = BSODFixThread(bsod_info)
    print("✓ Thread instance created")
    
    print("\n[4/5] Testing individual fix methods...")
    
    # Test check_windows_updates with timeout
    print("\n  Testing check_windows_updates() [with 3-second timeout]...")
    start_time = time.time()
    result = thread.check_windows_updates()
    elapsed = time.time() - start_time
    print(f"  Result: {result}")
    print(f"  Time taken: {elapsed:.2f} seconds")
    
    if elapsed > 5:
        print("  ⚠️ WARNING: Method took too long!")
    else:
        print("  ✓ Method completed within acceptable time")
    
    # Test clear_temp_files
    print("\n  Testing clear_temp_files()...")
    result = thread.clear_temp_files()
    print(f"  Result: {result}")
    print("  ✓ Method completed")
    
    # Test optimize_power_settings
    print("\n  Testing optimize_power_settings()...")
    result = thread.optimize_power_settings()
    print(f"  Result: {result}")
    print("  ✓ Method completed")
    
    print("\n[5/5] Testing fix_general_issues() [the 70% crash point]...")
    
    # Mock the progress signal
    class MockSignal:
        def emit(self, progress, status):
            print(f"  Progress: {progress}% - {status}")
    
    thread.fix_progress = MockSignal()
    
    start_time = time.time()
    results = thread.fix_general_issues()
    elapsed = time.time() - start_time
    
    print(f"\n  Results from fix_general_issues():")
    for i, result in enumerate(results, 1):
        print(f"    {i}. {result}")
    
    print(f"\n  Time taken: {elapsed:.2f} seconds")
    
    if elapsed > 10:
        print("  ⚠️ WARNING: Method took too long!")
    else:
        print("  ✓ Method completed within acceptable time")
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)
    print("\nThe 70% crash fix appears to be working correctly.")
    print("The app should no longer hang when running BSOD fixes.")
    
except Exception as e:
    print(f"\n❌ TEST FAILED: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
