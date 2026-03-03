#!/usr/bin/env python3
"""Test to reproduce the 80% crash"""

import sys
import time
import traceback

print("Testing for 80% crash in BSOD fix...\n")
print("=" * 60)

try:
    print("\n[1/6] Importing bsod_analyzer module...")
    from bsod_analyzer import BSODFixThread
    print("✓ Import successful")
    
    print("\n[2/6] Creating test BSOD info...")
    bsod_info = {
        'error_code': '0x0000000A',
        'error_name': 'IRQL_NOT_LESS_OR_EQUAL',
        'timestamp': '2024-01-01T12:00:00'
    }
    print(f"✓ Test data: {bsod_info['error_code']}")
    
    print("\n[3/6] Creating BSODFixThread instance...")
    thread = BSODFixThread(bsod_info)
    print("✓ Thread instance created")
    
    # Mock the progress signal
    class MockSignal:
        def emit(self, progress, status):
            print(f"  Progress: {progress}% - {status}")
            if progress == 80:
                print("  >>> REACHED 80% - Testing optimize_power_settings()...")
    
    thread.fix_progress = MockSignal()
    thread.fix_complete = MockSignal()
    thread.error_occurred = MockSignal()
    
    print("\n[4/6] Testing optimize_power_settings() directly...")
    start_time = time.time()
    try:
        result = thread.optimize_power_settings()
        elapsed = time.time() - start_time
        print(f"  Result: {result}")
        print(f"  Time taken: {elapsed:.2f} seconds")
        
        if elapsed > 10:
            print("  ⚠️ WARNING: Method took too long!")
        else:
            print("  ✓ Method completed successfully")
    except Exception as e:
        print(f"  ❌ CRASH IN optimize_power_settings(): {e}")
        traceback.print_exc()
        raise
    
    print("\n[5/6] Testing fix_general_issues() to reach 80%...")
    try:
        results = thread.fix_general_issues()
        print(f"\n  Results from fix_general_issues():")
        for i, result in enumerate(results, 1):
            print(f"    {i}. {result}")
        print("  ✓ fix_general_issues() completed successfully")
    except Exception as e:
        print(f"  ❌ CRASH IN fix_general_issues(): {e}")
        traceback.print_exc()
        raise
    
    print("\n[6/6] Running full thread.run() execution...")
    try:
        thread.run()
        print("  ✓ Full execution completed")
    except Exception as e:
        print(f"  ❌ CRASH IN thread.run(): {e}")
        traceback.print_exc()
        raise
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED - No crash at 80%")
    print("=" * 60)
    
except Exception as e:
    print(f"\n" + "=" * 60)
    print(f"❌ TEST FAILED - Crash detected!")
    print("=" * 60)
    print(f"\nError: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
