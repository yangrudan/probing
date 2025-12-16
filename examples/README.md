# Probing Examples

这个目录包含了 Probing 工具的各种使用示例。

## 示例列表

### demo_magics.py

**演示 Magics 模块如何将解释器从 CPython 切换到 IPython**

这个示例展示了 Probing 的核心特性之一：使用 IPython kernel 替代标准 Python 解释器，从而支持强大的 magic 命令和增强的交互式调试功能。

**运行方式：**
```bash
# 确保已安装 probing
pip install probing

# 运行示例
python examples/demo_magics.py
```

**示例内容：**
1. 对比标准 CPython 和 IPython kernel 的差异
2. 演示自定义 Magic 命令的使用（如 `%bt`, `%get_torch_modules`）
3. 展示 IPython kernel 的状态持久化特性
4. 演示多个 CodeExecutor 实例如何共享内核状态
5. 展示 DebugConsole 的交互式使用

**相关文档：**
- [Magics模块：IPython集成机制](../docs/src/design/magics-ipython-integration.md)

### test_probing.py

测试 probing 的基本功能，包括探针注入和数据采集。

### imagenet.py

演示在 ImageNet 训练任务中使用 probing 进行性能分析和调试。

### hooks.py

演示如何使用 probing 的 hook 机制来监控和修改代码执行行为。

### bench_profiler.py

性能基准测试，用于评估 profiler 的开销。

### job_tracker.py

演示如何使用 probing 追踪和监控作业执行。

## 使用说明

### 安装依赖

```bash
pip install probing
pip install torch  # 如果要运行 PyTorch 相关示例
```

### 运行示例

大多数示例可以直接运行：

```bash
python examples/test_probing.py
```

某些示例需要启用 probing 探针：

```bash
PROBING=1 python examples/test_probing.py
```

### 远程调试

你也可以向运行中的进程注入探针：

```bash
# 在一个终端运行目标程序
python examples/test_probing.py

# 在另一个终端注入探针
probing -t <pid> inject

# 连接 REPL 进行交互式调试
probing -t <pid> repl
```

## 更多信息

详细的使用文档请参考：
- [系统架构](../docs/src/design/architecture.md)
- [调试机制](../docs/src/design/debugging.md)
- [性能分析](../docs/src/design/profiling.md)
