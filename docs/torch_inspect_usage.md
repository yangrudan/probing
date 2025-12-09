# When is python/probing/inspect/torch.py Triggered?

## Overview

The `python/probing/inspect/torch.py` module is **automatically loaded when you import the probing library**. This happens through a chain of imports in the probing package initialization.

## Import Chain

```
import probing
  └─> probing/__init__.py (line 58)
      └─> import probing.inspect
          └─> probing/inspect/__init__.py (lines 1-3)
              └─> from .torch import get_torch_modules, get_torch_tensors, get_torch_optimizers
                  └─> probing/inspect/torch.py is loaded
```

### Detailed Explanation

1. **Package Initialization** (`python/probing/__init__.py`, line 58):
   ```python
   import probing.inspect
   ```
   When you `import probing`, the package's `__init__.py` automatically imports the `probing.inspect` module.

2. **Inspect Module Initialization** (`python/probing/inspect/__init__.py`, lines 1-3):
   ```python
   from .torch import get_torch_modules
   from .torch import get_torch_tensors
   from .torch import get_torch_optimizers
   ```
   The inspect module's `__init__.py` immediately imports functions from `torch.py`, which causes the entire `torch.py` module to be loaded.

## What Does torch.py Do?

The `torch.py` module provides functionality to track and inspect PyTorch objects (Tensors, Modules, and Optimizers) in memory:

### Key Features:

1. **Cache Management**: Maintains weak reference caches for:
   - `tensor_cache`: PyTorch tensors
   - `module_cache`: PyTorch modules (neural network layers/models)
   - `optim_cache`: PyTorch optimizers

2. **Automatic Refresh**: Periodically refreshes the cache (every 5 minutes by default) to ensure dead references are cleaned up.

3. **Public API Functions**:
   - `get_torch_modules()`: Returns list of active PyTorch modules in memory
   - `get_torch_tensors()`: Returns list of active PyTorch tensors in memory
   - `get_torch_optimizers()`: Returns list of active PyTorch optimizers in memory

## When Are These Functions Used?

### 1. Direct Python Usage

Users can query torch objects programmatically:

```python
import probing
from probing.inspect import get_torch_modules, get_torch_tensors, get_torch_optimizers

# Get all PyTorch modules in memory
modules = get_torch_modules()
for module in modules:
    print(f"Module ID: {module['id']}, Type: {module['type']}")

# Get all PyTorch tensors
tensors = get_torch_tensors()
```

### 2. IPython Magic Commands

The module is used by IPython magic commands defined in `python/probing/magics/handle_magic.py`:

```python
# In IPython/Jupyter notebook with probing loaded:
%get_torch_tensors limit=10
%get_torch_modules toplevel=True
```

**Note**: The magic commands in `handle_magic.py` currently use `gc.get_objects()` directly instead of calling the cached functions from `torch.py`. This appears to be redundant implementation.

### 3. SQL Query Interface (Potential Use)

The Rust side has a Python plugin that can evaluate Python expressions (see `probing/extensions/python/src/extensions/python/tbls.rs`). The functions could potentially be queried via SQL:

```sql
SELECT * FROM python.probing.inspect.get_torch_modules()
```

This works through the `data_from_python()` function which evaluates Python expressions and converts results to record batches.

## Cache Update Mechanism

The cache is **NOT automatically populated** when torch.py loads. Instead:

1. **Manual Update**: Call `update_cache(obj)` to add a specific object
2. **Full Refresh**: Call `refresh_cache()` to scan all objects in memory using `gc.get_objects()`
3. **Automatic Refresh**: Happens automatically when:
   - `get_torch_modules()`, `get_torch_tensors()`, or `get_torch_optimizers()` is called
   - AND more than 5 minutes (FULL_REFRESH_INTERVAL_SECONDS) have passed since last refresh
   - OR when dead weak references are detected in the cache

## Why Does This Matter?

### Performance Consideration

Loading `torch.py` on every `import probing` has minimal overhead because:

1. The module only defines functions and initializes empty dictionaries
2. It does NOT import torch at module load time
3. The actual `import torch` only happens when functions are called (lazy import on line 13)

### Potential Issue

If PyTorch is not installed, importing probing will still succeed. The torch-specific functions will only fail when actually called, which is appropriate behavior.

## Debug Output: "!!loader" Messages

If you see messages like:
```
!!loader probing.inspect
!!loader probing.inspect.torch
```

This indicates debug logging is enabled in the import system. These messages are NOT in the current codebase and may come from:
- A development/debug build
- Custom environment configuration
- Modified import hooks with debug output

## Recommendations for Users

1. **Normal Usage**: Simply `import probing` - torch inspection is available automatically
2. **Performance**: The lazy import of torch means no overhead unless you use torch-specific features
3. **No PyTorch Required**: You can use probing without PyTorch installed; torch features simply won't work

## Summary

**Answer**: `python/probing/inspect/torch.py` is triggered immediately when you `import probing` due to the import chain in the package initialization. However, PyTorch itself is only imported when you actually call the torch inspection functions, making this a lightweight dependency.
