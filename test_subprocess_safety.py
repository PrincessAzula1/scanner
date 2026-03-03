#!/usr/bin/env python3
"""Stress test all subprocess calls to ensure no crashes"""

import sys
import time
import traceback

print("Stress Testing All Fix Operations...\n")
print("=" * 60)

try:
    print("\n[1/8] Importing bsod_analyzer...")
    from bsod_analyzer import BSODFixThread
    print("✓ Import successful")
    
    print("\n[2/8] Creating BSODFixThread instance...")
    bsod_info = {
        'error_code': '0x0000000A',
        'error_name': 'IRQL_NOT_LESS_OR_EQUAL',
        'timestamp': '2024-01-01T12:00:00'
    }
    thread = BSODFixThread(bsod_info)
    print("✓ Thread instance created")
    
    print("\n[3/8] Testing optimize_power_settings() [80% operation]...")
    start = time.time()
    result = thread.optimize_power_settings()
    elapsed = time.time() - start
    print(f"  Result: {result}")
    print(f"  Time: {elapsed:.2f}s")
    assert elapsed < 5, "optimize_power_settings took too long!"
    print("  ✓ Passed")
    
    print("\n[4/8] Testing schedule_memory_diagnostic()...")
    start = time.time()
    result = thread.schedule_memory_diagnostic()
    elapsed = time.time() - start
    print(f"  Result: {result}")
    print(f"  Time: {elapsed:.2f}s")
    assert elapsed < 5, "schedule_memory_diagnostic took too long!"
    print("  ✓ Passed")
    
    print("\n[5/8] Testing run_system_file_checker() [long timeout]...")
    start = time.time()
    result = thread.run_system_file_checker()
    elapsed = time.time() - start
    print(f"  Result: {result}")
    print(f"  Time: {elapsed:.2f}s")
    assert elapsed < 185, "run_system_file_checker exceeded timeout!"
    print("  ✓ Passed")
    
    print("\n[6/8] Testing run_disk_check()...")
    start = time.time()
    result = thread.run_disk_check()
    elapsed = time.time() - start
    print(f"  Result: {result}")
    print(f"  Time: {elapsed:.2f}s")
    assert elapsed < 10, "run_disk_check took too long!"
    print("  ✓ Passed")
    
    print("\n[7/8] Testing update_problematic_drivers()...")
    start = time.time()
    result = thread.update_problematic_drivers()
    elapsed = time.time() - start
    print(f"  Result: {result}")
    print(f"  Time: {elapsed:.2f}s")
    assert elapsed < 35, "update_problematic_drivers took too long!"
    print("  ✓ Passed")
    
    print("\n[8/8] Testing full fix_general_issues() [includes 80%]...")
    
    class MockSignal:
        def emit(self, progress, status):
            print(f"  {progress}% - {status}")
    
    thread.fix_progress = MockSignal()
    
    start = time.time()
    results = thread.fix_general_issues()
    elapsed = time.time() - start
    
    print(f"\n  Completed in {elapsed:.2f}s")
    print(f"  Results: {len(results)} operations")
    for i, result in enumerate(results, 1):
        print(f"    {i}. {result}")
    
    assert elapsed < 15, "fix_general_issues took too long!"
    assert len(results) > 0, "No results returned!"
    print("  ✓ Passed")
    
    print("\n" + "=" * 60)
    print("✅ ALL STRESS TESTS PASSED!")
    print("=" * 60)
    print("\nAll subprocess operations are safe and won't crash at 80%.")
    print("Timeouts and error handling are working correctly.")
    
except AssertionError as e:
    print(f"\n❌ ASSERTION FAILED: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ TEST CRASHED: {e}")
    traceback.print_exc()
    sys.exit(1)
