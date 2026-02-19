import traceback
try:
    from storage_diagnostic import StorageDiagnosticWidget
    print('✓ Import successful!')
except Exception as e:
    print(f'✗ Error: {e}')
    traceback.print_exc()
