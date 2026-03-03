#!/usr/bin/env python3
"""Stress test to simulate actual GUI scenario"""

import sys
import time
import traceback
from PyQt6.QtCore import QThread, pyqtSignal, QCoreApplication

print("Simulating actual GUI thread behavior...\n")
print("=" * 60)

try:
    # Create a Qt application
    app = QCoreApplication(sys.argv)
    
    print("\n[1/3] Importing BSODFixThread...")
    from bsod_analyzer import BSODFixThread
    print("✓ Import successful")
    
    print("\n[2/3] Creating thread with actual Qt signals...")
    bsod_info = {
        'error_code': '0x0000000A',
        'error_name': 'IRQL_NOT_LESS_OR_EQUAL',
        'timestamp': '2024-01-01T12:00:00'
    }
    thread = BSODFixThread(bsod_info)
    
    # Track progress
    progress_tracker = {'crashed': False, 'last_progress': 0, 'completed': False}
    
    def on_progress(progress, status):
        print(f"  Progress: {progress}% - {status}")
        progress_tracker['last_progress'] = progress
        if progress == 80:
            print("  >>> REACHED 80% IN GUI CONTEXT")
    
    def on_complete(report):
        print("\n✅ Thread completed successfully!")
        print(f"Report preview: {report[:200]}...")
        progress_tracker['completed'] = True
        app.quit()
    
    def on_error(error_msg):
        print(f"\n❌ Thread error at {progress_tracker['last_progress']}%: {error_msg}")
        progress_tracker['crashed'] = True
        app.quit()
    
    # Connect signals
    thread.fix_progress.connect(on_progress)
    thread.fix_complete.connect(on_complete)
    thread.error_occurred.connect(on_error)
    
    print("✓ Signals connected")
    
    print("\n[3/3] Starting thread (actual Qt threading)...")
    thread.start()
    
    # Set a timeout
    from PyQt6.QtCore import QTimer
    def timeout_check():
        if not progress_tracker['completed'] and not progress_tracker['crashed']:
            if thread.isRunning():
                print(f"\n⚠️ Thread still running... Last progress: {progress_tracker['last_progress']}%")
            else:
                print(f"\n⚠️ Thread stopped unexpectedly at {progress_tracker['last_progress']}%")
                progress_tracker['crashed'] = True
                app.quit()
    
    QTimer.singleShot(15000, timeout_check)  # 15 second timeout
    
    # Run the event loop
    print("✓ Running Qt event loop...\n")
    app.exec()
    
    print("\n" + "=" * 60)
    if progress_tracker['completed']:
        print("✅ TEST PASSED - No crash in GUI context")
    elif progress_tracker['crashed']:
        print(f"❌ TEST FAILED - Crashed at {progress_tracker['last_progress']}%")
        sys.exit(1)
    else:
        print("⚠️ Test inconclusive")
    print("=" * 60)
    
except Exception as e:
    print(f"\n" + "=" * 60)
    print(f"❌ TEST CRASHED: {e}")
    print("=" * 60)
    traceback.print_exc()
    sys.exit(1)
