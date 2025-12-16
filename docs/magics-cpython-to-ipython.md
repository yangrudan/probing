# Magics模块如何将解释器从CPython切换到IPython

## 问题回答

Magics模块通过以下关键技术实现了从CPython到IPython的解释器切换：

## 核心机制

### 1. 使用InProcessKernelManager

```python
from ipykernel.inprocess.manager import InProcessKernelManager

class CodeExecutor:
    def __init__(self):
        # 创建进程内的IPython kernel管理器
        self.km = InProcessKernelManager()
        # 启动kernel
        self.km.start_kernel()
        # 创建客户端
        self.kc = self.km.client()
        # 启动通信通道
        self.kc.start_channels()
```

**关键点：**
- `InProcessKernelManager` 在同一个Python进程内创建一个IPython kernel
- 不需要启动独立的进程或通过网络通信
- 直接在当前进程中获得完整的IPython功能

### 2. 替代标准exec()函数

**CPython标准方式：**
```python
exec(code, globals(), locals())  # 直接执行代码
```

**IPython Kernel方式：**
```python
def execute(self, code):
    # 通过IPython kernel执行
    self.kc.execute(code, silent=False)
    
    # 获取执行结果
    reply = self.kc.get_shell_msg(timeout=5)
    
    # 收集输出
    output = []
    while self.kc.iopub_channel.msg_ready():
        sub_msg = self.kc.get_iopub_msg(timeout=5)
        # ... 处理输出
```

### 3. 自动注册Magic命令

```python
if self.km.has_kernel:
    shell = self.km.kernel.shell
    # 注册各种自定义magic命令
    shell.register_magics(TorchMagic(shell=shell))
    shell.register_magics(DebugMagic(shell=shell))
    shell.register_magics(StackMagic(shell=shell))
    shell.register_magics(HandleMagic(shell=shell))
```

## 实现效果对比

### CPython无法做到的事情

```python
# CPython中会报语法错误
>>> %timeit x + 1
SyntaxError: invalid syntax

>>> %tprofile steps=5
SyntaxError: invalid syntax
```

### IPython Kernel可以做到

```python
# 通过CodeExecutor执行
>>> executor.execute("%bt")  # 打印Python堆栈
>>> executor.execute("%tprofile steps=5")  # PyTorch性能分析
>>> executor.execute("%dump_stack")  # 显示详细堆栈信息
>>> executor.execute("%get_torch_modules")  # 获取PyTorch模块
```

## 技术架构

```
用户代码
   ↓
CodeExecutor.execute(code)
   ↓
InProcessKernelClient.execute(code)
   ↓
IPython InteractiveShell
   ↓ (解析magic命令)
   ↓
TorchMagic / DebugMagic / StackMagic / HandleMagic
   ↓
返回结果 (ExecutionResult)
```

## 为什么这样设计？

### 1. **功能增强**
- CPython只能执行基本的Python代码
- IPython提供magic命令、更好的错误处理、富文本输出等

### 2. **调试能力**
- 可以动态注入各种调试命令
- 支持远程调试（`%remote_debug`）
- 支持性能分析（`%tprofile`）

### 3. **用户体验**
- 对用户透明：执行普通Python代码没有区别
- 额外支持：可以使用magic命令增强功能
- 状态持久：多次执行之间共享变量

## 实际应用场景

### 远程进程调试
```bash
# 连接到远程进程
probing -t <pid> repl

# 在远程进程中执行magic命令
>>> %bt                    # 查看堆栈
>>> %dump_stack            # 详细堆栈
>>> %get_torch_modules     # 查看PyTorch模块
>>> %tprofile steps=10     # 性能分析
>>> %remote_debug port=9999 # 启动远程调试
```

### 进程内代码执行
```python
from probing.magics import CodeExecutor

executor = CodeExecutor()

# 执行普通Python代码
executor.execute("import torch")
executor.execute("x = torch.randn(3, 3)")

# 使用magic命令
executor.execute("%tprofile steps=5")
executor.execute("%tsummary")
```

## 关键技术总结

1. **InProcessKernelManager**：在同一进程内创建IPython kernel
2. **消息通道**：通过Shell和IOPub通道进行通信
3. **Magic注册**：使用`@magics_class`和`@line_magic`定义自定义命令
4. **状态共享**：多个CodeExecutor实例共享同一个InteractiveShell
5. **透明切换**：对普通Python代码完全兼容

## 详细文档

完整的技术细节和实现原理，请参考：
- [Magics模块：IPython集成机制](../docs/src/design/magics-ipython-integration.md)
- [示例代码](../examples/demo_magics.py)
