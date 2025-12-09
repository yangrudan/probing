# python/probing/inspect/torch.py 什么时候触发使用？

## 概述

`python/probing/inspect/torch.py` 模块在**导入 probing 库时会自动加载**。这是通过 probing 包初始化时的一系列导入链实现的。

## 导入链

```
import probing
  └─> probing/__init__.py (第58行)
      └─> import probing.inspect
          └─> probing/inspect/__init__.py (第1-3行)
              └─> from .torch import get_torch_modules, get_torch_tensors, get_torch_optimizers
                  └─> probing/inspect/torch.py 被加载
```

### 详细说明

1. **包初始化** (`python/probing/__init__.py`, 第58行):
   ```python
   import probing.inspect
   ```
   当你执行 `import probing` 时，包的 `__init__.py` 会自动导入 `probing.inspect` 模块。

2. **Inspect 模块初始化** (`python/probing/inspect/__init__.py`, 第1-3行):
   ```python
   from .torch import get_torch_modules
   from .torch import get_torch_tensors
   from .torch import get_torch_optimizers
   ```
   inspect 模块的 `__init__.py` 立即从 `torch.py` 导入函数，这会导致整个 `torch.py` 模块被加载。

## torch.py 做了什么？

`torch.py` 模块提供了在内存中跟踪和检查 PyTorch 对象（Tensor、Module 和 Optimizer）的功能：

### 主要特性：

1. **缓存管理**: 维护弱引用缓存用于：
   - `tensor_cache`: PyTorch 张量
   - `module_cache`: PyTorch 模块（神经网络层/模型）
   - `optim_cache`: PyTorch 优化器

2. **自动刷新**: 定期刷新缓存（默认每5分钟）以确保清理失效的引用。

3. **公共 API 函数**:
   - `get_torch_modules()`: 返回内存中活跃的 PyTorch 模块列表
   - `get_torch_tensors()`: 返回内存中活跃的 PyTorch 张量列表
   - `get_torch_optimizers()`: 返回内存中活跃的 PyTorch 优化器列表

## 这些函数什么时候被使用？

### 1. 直接的 Python 使用

用户可以通过编程方式查询 torch 对象：

```python
import probing
from probing.inspect import get_torch_modules, get_torch_tensors, get_torch_optimizers

# 获取内存中所有 PyTorch 模块
modules = get_torch_modules()
for module in modules:
    print(f"模块 ID: {module['id']}, 类型: {module['type']}")

# 获取所有 PyTorch 张量
tensors = get_torch_tensors()
```

### 2. IPython 魔法命令

该模块被 `python/probing/magics/handle_magic.py` 中定义的 IPython 魔法命令使用：

```python
# 在加载了 probing 的 IPython/Jupyter notebook 中：
%get_torch_tensors limit=10
%get_torch_modules toplevel=True
```

**注意**: `handle_magic.py` 中的魔法命令当前直接使用 `gc.get_objects()`，而不是调用 `torch.py` 中的缓存函数。这似乎是重复实现。

### 3. SQL 查询接口（潜在用途）

Rust 端有一个 Python 插件可以执行 Python 表达式（见 `probing/extensions/python/src/extensions/python/tbls.rs`）。这些函数可能通过 SQL 查询：

```sql
SELECT * FROM python.probing.inspect.get_torch_modules()
```

这通过 `data_from_python()` 函数工作，该函数执行 Python 表达式并将结果转换为记录批次。

## 缓存更新机制

当 torch.py 加载时，缓存**不会**自动填充。相反：

1. **手动更新**: 调用 `update_cache(obj)` 添加特定对象
2. **完全刷新**: 调用 `refresh_cache()` 使用 `gc.get_objects()` 扫描内存中的所有对象
3. **自动刷新**: 在以下情况下自动发生：
   - 调用 `get_torch_modules()`、`get_torch_tensors()` 或 `get_torch_optimizers()` 时
   - 且距离上次刷新已超过5分钟（FULL_REFRESH_INTERVAL_SECONDS）
   - 或在缓存中检测到失效的弱引用时

## 为什么这很重要？

### 性能考虑

在每次 `import probing` 时加载 `torch.py` 的开销很小，因为：

1. 该模块只定义函数并初始化空字典
2. 在模块加载时**不会**导入 torch
3. 实际的 `import torch` 只在函数被调用时发生（第13行的懒加载）

### 潜在问题

如果未安装 PyTorch，导入 probing 仍然会成功。torch 特定的函数只有在实际调用时才会失败，这是适当的行为。

## 调试输出："!!loader" 消息

如果你看到类似以下的消息：
```
!!loader probing.inspect
!!loader probing.inspect.torch
```

这表明导入系统中启用了调试日志记录。这些消息**不在**当前代码库中，可能来自：
- 开发/调试构建版本
- 自定义环境配置
- 带有调试输出的修改过的导入钩子

## 用户建议

1. **正常使用**: 只需 `import probing` - torch 检查功能会自动可用
2. **性能**: torch 的懒加载意味着除非使用 torch 特定功能，否则没有开销
3. **不需要 PyTorch**: 可以在不安装 PyTorch 的情况下使用 probing；torch 功能只是不工作而已

## 总结

**答案**: `python/probing/inspect/torch.py` 在你执行 `import probing` 时会立即触发，这是由于包初始化中的导入链。但是，PyTorch 本身只在你实际调用 torch 检查函数时才被导入，这使其成为一个轻量级的依赖。

## 关于 ProbingLoader 的说明

你提到的输出：
```python
>>> import probing
!!loader probing.inspect
!!loader probing.inspect.torch
```

这些 `!!loader` 消息表明有调试日志被打印。虽然当前代码库中没有这些打印语句，但这可以通过以下方式解释：

1. **自定义导入钩子**: 你的环境中可能有修改过的 `ProbingLoader`，添加了调试输出
2. **开发版本**: 可能使用的是包含额外日志记录的开发版本
3. **环境配置**: 某些环境变量或配置可能启用了详细的导入跟踪

这些加载器消息证实了导入链的行为：当 `probing` 被导入时，`probing.inspect` 和 `probing.inspect.torch` 确实被加载了。
