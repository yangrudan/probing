#!/usr/bin/env python
"""
演示 Magics 模块如何将解释器从 CPython 切换到 IPython

这个示例展示了：
1. CodeExecutor 如何使用 IPython kernel 代替标准 Python exec
2. 如何使用自定义 Magic 命令
3. IPython kernel 的状态持久化特性
"""

import sys
import time


def demo_standard_python():
    """标准 Python 解释器示例"""
    print("\n" + "="*60)
    print("1. 标准 CPython 解释器")
    print("="*60)
    
    # 标准 Python 的 exec
    code = """
x = 42
print(f"x = {x}")
"""
    print(f"执行代码:\n{code}")
    
    namespace = {}
    exec(code, namespace)
    
    # 尝试执行 magic 命令（会失败）
    try:
        exec("%timeit x + 1", namespace)
    except SyntaxError as e:
        print(f"\n⚠️  CPython 不支持 Magic 命令: {e}")


def demo_ipython_kernel():
    """IPython kernel 解释器示例"""
    print("\n" + "="*60)
    print("2. IPython Kernel 解释器")
    print("="*60)
    
    try:
        from probing.magics import CodeExecutor, ExecutionResult
    except ImportError:
        print("⚠️  无法导入 probing.magics 模块")
        print("请确保已安装 ipykernel: pip install ipykernel")
        return
    
    # 创建 CodeExecutor
    print("\n创建 CodeExecutor（使用 IPython kernel）...")
    executor = CodeExecutor()
    
    # 执行普通代码
    print("\n执行普通 Python 代码:")
    code = "x = 42\nprint(f'x = {x}')"
    print(f"代码: {code}")
    result = executor.execute(code)
    result.display()
    
    # 执行带有魔法命令的代码
    print("\n执行自定义 Magic 命令:")
    
    # 测试 %bt (backtrace)
    print("\n➤ 测试 %bt 命令（打印 Python 堆栈）:")
    result = executor.execute("%bt")
    if result.status == "ok":
        print("✓ Magic 命令执行成功")
        if result.output:
            lines = result.output.split('\n')[:5]  # 只显示前5行
            print("输出（前5行）:")
            for line in lines:
                print(f"  {line}")
    else:
        print("✗ 执行失败")
        result.display()
    
    # 测试状态持久化
    print("\n" + "="*60)
    print("3. 测试状态持久化")
    print("="*60)
    
    # 第一次执行
    print("\n第一次执行: 定义变量")
    result1 = executor.execute("import torch\nmy_tensor = torch.randn(3, 3)")
    print(f"状态: {result1.status}")
    
    # 第二次执行 - 使用之前定义的变量
    print("\n第二次执行: 使用之前定义的变量")
    result2 = executor.execute("print(f'Tensor shape: {my_tensor.shape}')")
    result2.display()
    
    # 测试自定义 magic 命令
    print("\n" + "="*60)
    print("4. 自定义 Magic 命令")
    print("="*60)
    
    print("\n➤ 测试 %get_torch_modules 命令:")
    result = executor.execute("%get_torch_modules limit=5")
    if result.status == "ok":
        print("✓ Magic 命令执行成功")
        if result.output:
            print(f"输出: {result.output[:200]}...")  # 只显示前200个字符
    else:
        print("注意: 没有找到 torch 模块（这是正常的，因为我们还没有创建模型）")
    
    # 清理
    print("\n关闭 executor...")
    executor.shutdown()


def demo_debug_console():
    """DebugConsole 示例"""
    print("\n" + "="*60)
    print("5. DebugConsole 交互式控制台")
    print("="*60)
    
    try:
        from probing.magics import DebugConsole
    except ImportError:
        print("⚠️  无法导入 DebugConsole")
        return
    
    # 创建 DebugConsole
    print("\n创建 DebugConsole...")
    console = DebugConsole()
    
    # 执行一些代码
    test_commands = [
        "x = 100",
        "print(x * 2)",
        "import math",
        "print(math.pi)",
    ]
    
    print("\n执行命令序列:")
    for cmd in test_commands:
        print(f"\n>>> {cmd}")
        result = console.push(cmd)
        if result:
            import json
            result_obj = json.loads(result)
            if result_obj.get("status") == "ok" and result_obj.get("output"):
                print(result_obj["output"])


def demo_shared_state():
    """演示多个 CodeExecutor 实例共享状态"""
    print("\n" + "="*60)
    print("6. 共享内核状态（重要特性）")
    print("="*60)
    
    try:
        from probing.magics import CodeExecutor
    except ImportError:
        print("⚠️  无法导入 CodeExecutor")
        return
    
    # 创建两个 executor 实例
    print("\n创建两个不同的 CodeExecutor 实例...")
    executor1 = CodeExecutor()
    executor2 = CodeExecutor()
    
    print(f"executor1 和 executor2 是不同的对象: {executor1 is not executor2}")
    
    # 在第一个 executor 中定义变量
    print("\n在 executor1 中定义变量:")
    executor1.execute("shared_var = 'Hello from executor1'")
    print("已执行: shared_var = 'Hello from executor1'")
    
    # 在第二个 executor 中访问该变量
    print("\n在 executor2 中访问该变量:")
    result = executor2.execute("print(shared_var)")
    result.display()
    
    print("\n✓ 这证明了两个 executor 实例共享同一个 IPython kernel 状态！")
    
    # 清理
    executor1.shutdown()
    executor2.shutdown()


def main():
    print("\n" + "="*70)
    print(" Magics 模块：从 CPython 到 IPython 的解释器切换演示")
    print("="*70)
    
    # 演示标准 Python
    demo_standard_python()
    
    # 演示 IPython kernel
    demo_ipython_kernel()
    
    # 演示 DebugConsole
    demo_debug_console()
    
    # 演示共享状态
    demo_shared_state()
    
    print("\n" + "="*70)
    print("演示完成！")
    print("="*70)
    print("\n总结:")
    print("1. CPython 使用 exec() 执行代码，不支持 magic 命令")
    print("2. IPython kernel 提供了增强的代码执行环境，支持 magic 命令")
    print("3. CodeExecutor 使用 InProcessKernelManager 创建进程内的 IPython kernel")
    print("4. 多个 CodeExecutor 实例共享同一个 InteractiveShell 状态")
    print("5. DebugConsole 将 CodeExecutor 包装成交互式控制台")
    print("\n详细文档请参考: docs/src/design/magics-ipython-integration.md")


if __name__ == "__main__":
    main()
