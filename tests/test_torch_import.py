#!/usr/bin/env python3
"""
Test script to verify when probing.inspect.torch is loaded.

This script demonstrates the import chain described in the documentation.
"""

import sys
import importlib.util

def check_module_loaded(module_name):
    """Check if a module is loaded in sys.modules"""
    return module_name in sys.modules

def main():
    print("=== Testing probing.inspect.torch Import Behavior ===\n")
    
    # Check initial state
    print("Before importing probing:")
    print(f"  - 'probing' loaded: {check_module_loaded('probing')}")
    print(f"  - 'probing.inspect' loaded: {check_module_loaded('probing.inspect')}")
    print(f"  - 'probing.inspect.torch' loaded: {check_module_loaded('probing.inspect.torch')}")
    print(f"  - 'torch' loaded: {check_module_loaded('torch')}")
    print()
    
    # Import probing
    print("Importing probing...")
    try:
        import probing
        print("✓ Successfully imported probing\n")
    except Exception as e:
        print(f"✗ Failed to import probing: {e}\n")
        return
    
    # Check state after importing probing
    print("After importing probing:")
    print(f"  - 'probing' loaded: {check_module_loaded('probing')}")
    print(f"  - 'probing.inspect' loaded: {check_module_loaded('probing.inspect')}")
    print(f"  - 'probing.inspect.torch' loaded: {check_module_loaded('probing.inspect.torch')}")
    print(f"  - 'torch' loaded: {check_module_loaded('torch')}")
    print()
    
    # Verify the import chain
    print("Verification:")
    if check_module_loaded('probing.inspect.torch'):
        print("✓ probing.inspect.torch was loaded automatically")
    else:
        print("✗ probing.inspect.torch was NOT loaded")
    
    if not check_module_loaded('torch'):
        print("✓ PyTorch itself was NOT imported (lazy import works)")
    else:
        print("⚠ PyTorch was imported (may be expected if torch is already installed)")
    print()
    
    # Test calling a torch inspection function
    print("Testing torch inspection function call:")
    try:
        from probing.inspect import get_torch_modules
        print("✓ Successfully imported get_torch_modules")
        
        # Call the function (this should trigger torch import if available)
        try:
            modules = get_torch_modules()
            print(f"✓ get_torch_modules() returned {len(modules)} modules")
            print(f"  - 'torch' loaded after function call: {check_module_loaded('torch')}")
        except ImportError as e:
            print(f"⚠ Cannot call get_torch_modules() - PyTorch not installed: {e}")
        except Exception as e:
            print(f"✗ Error calling get_torch_modules(): {e}")
    except Exception as e:
        print(f"✗ Failed to import get_torch_modules: {e}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
