#import "@preview/slydst:0.1.1": *

#import "@preview/gentle-clues:0.9.0": *
#import "@preview/showybox:2.0.1": showybox
#import "@preview/fletcher:0.5.1" as fletcher: diagram, node, edge
#import "@preview/codelst:2.0.1": sourcecode

#set text(size: 14pt)
#show link: underline
// #show: codly-init.with()

#show: slides.with(
  title: "Probing -- 性能与稳定性诊断工具",
  subtitle: "一种非侵入式诊断工具",
  date: "2024.07.20",
  authors: ("侯杰"),
  layout: "large",
  ratio: 16 / 9,
  title-color: none,
)

== Outline

#outline()

= Overview

== 大模型训练的几个典型问题
- 稳定性问题
- 性能问题
- 精度问题

== 为何需要Probing?
#grid(
  columns: (1fr, 2fr),
  [
    常见分析与诊断任务

    - 热点分析
    - 时序分析
    - 峰值内存
    - 通信分析
    - 排查hang
    - 排查跑飞
  ],
  [
    分析工作的痛点：
    - 工具繁杂：每种任务都有不同的工具；
    - 事前药物：晕车前来一片，不是后悔药;

    Probing 的设计：
    - 紧急药物（Emergency）：晕车时服用，而无需事先服用；
    - 全范围（fleet-wide）：提供完备的诊断与分析能力，无需轮番切换工具；

  ],
)

= 整体设计

== 整体设计
#grid(
  columns: (3fr, 2fr),
  image("imgs/probing.jpg"),
  [
    核心设计：探针
    - 探针可在任意时刻被注入;
    - 探针通过插件实现功能；
    - 探针接受多种远程控制；
  ],
)
]

== 交互设计
#columns(2)[
  #set text(size: 11pt)
  #set table(
    align: left + horizon,
    columns: (2fr, 3fr),
    stroke: (x, y) => (
      left: none,
      right: none,
      top: none,
      bottom: if y == 0 {
        rgb("21222C")
      } else {
        0pt
      },
    ),
    fill: (x, y) => {
      if calc.odd(y) {
        rgb("F2F2F2")
      } else {
        none
      }
    },
  )
  #set table.header(repeat: false)
  #show table.cell.where(y: 0): set text(weight: "bold", size: 12pt)
  #show table.cell.where(y: 0): it => {
    table.cell(colspan: 2)[#it]
  }
  #table(
    table.header[探针注入],
    [`ptrace`注入],[`probing 1234 inject`],
    [`LD_PRELOAD` 注入],[`LD_PRELOAD=<...>/libprobing.so python`],
    [代码注入],[```
      import probing
      probing.init()
      ```]
  )
  #colbreak()
  #table(
    table.header[显示信息],
    [内存信息],[`probing <pid/addr> show memory`],
    [], [`probing <pid/addr> repl`

      `(repl)>> show memory` (下同)],
    [线程信息],[`probing <pid/addr> show threads`],
    // [], [`(repl)>> show threads`],
    [Python对象],[`probing <pid/addr> show objects`],
    // [], [`(repl)>> show objects`],
    [tensor对象],[`probing <pid/addr> show tensors`],
    // [], [`(repl)>> show tensors`],
    [module对象],[`probing <pid/addr> show modules`],
    // [], [`(repl)>> show modules`],
    [plt条目],[`probing <pid/addr> show plt`],
    // [], [`(repl)>> show plt`],
  )
  #colbreak()

  #table(
    table.header[启用特性],
    [启用pprof],[`probing <pid/addr> enable pprof`],
    [], [`probing <pid/addr> repl`

      `(repl)>> enable pprof` (下同)],
    [启用dap调试],[`probing <pid/addr> enable dap <addr>`],
    [启用远程调试],[`probing <pid> enable remote <addr>`],
    [启用crash处理],[`probing <pid> enable catch-crash <addr>`],
  )
  #colbreak()

  #table(
    table.header[关闭特性],
    [关闭pprof],[`probing <pid/addr> disable pprof`],
    [], [`probing <pid/addr> repl`

      `(repl)>> disable pprof` (下同)],
    [关闭dap调试],[`probing <pid/addr> disable dap <addr>`],
    [关闭远程调试],[`probing <pid> disable remote <addr>`],
    [关闭crash处理],[`probing <pid> disable catch-crash <addr>`],
  )
  #colbreak()

  #table(
    table.header[backtrace],
    [显示c/c++调用栈],[`probing <pid/addr> backtrace show --cc`],
    [], [`probing <pid/addr> repl`

      `(repl)>> backtrace show --cc` (下同)],
    [显示Python调用栈],[`(repl)>> bt show --python`],
    [显示某线程调用栈],[`(repl)>> bt show --tid <tid>`],
  )

  #table(
    table.header[注入并执行代码],
    [显示c/c++调用栈],[`probing <pid/addr> eval "print(1234)"`],
    [], [`probing <pid/addr> repl`

      `(repl)>> eval "print(1234)"` (下同)],
  )
  #colbreak()

  #table(
    table.header[使用panel/web界面],
    [访问panel], [`probing <pid/addr> panel`],
    [
      #image("imgs/panel.png")
    ],[
      `tab`键切换panel

      方向键浏览信息

      `Enter`键查看详情
    ],
    [访问web], [`probing <pid> enable remote 127.0.0.1:9922`],
    [#image("imgs/webui.png")],[

      浏览器访问：http://127.0.0.1:9922
    ]
  )
]

= 机制实现

=== `probing` 提供一些相关机制的实现
#columns(2)[
  - backtrace机制
    - 抓取c/c++
    - 抓取python
  - hook机制
    - hook python函数
    - hook c/c++函数

  #colbreak()

  - inspect机制
    - inspect python 对象
    - inspect c/c++ 内存

  - tracing机制
    - trace python执行
    - trace c/c++ 函数执行
]

=== 与异构设备的集成

- 抓取Device执行信息
  - 读取Device执行情况
  - 关联Host与Device侧调用
- 性能计数器
  - Host侧性能计数器
  - Device侧性能计数器

== backtrace机制 -- 抓取C/C++

=== 数据采集
- 使用`setitimer(which: i32, new: *timerval, old: *timerval)`, 周期性发送`SIGALRM`、`SIGVTALRM`或者`SIGPROF`信号给当前进程；
- `SIGPROF`会dispatch给处于`RUNNING`状态的随机线程；
- `SIGPROF`的handler里进行backtrace与数据存储；
- 使用 #link("https://crates.io/crates/backtrace")[backtrace-rs]，支持cpp_demangle；
=== flamegraph输出
- 使用#link("https://crates.io/crates/inferno")[inferno]输出flamegraph；
- 支持从http输出到浏览器；
#pagebreak()

=== TODO
- 进一步降低backtrace的开销：
  - backtrace捕获与symbol resolve异步执行化；
  - 对busy symbol进行cache；
- flamegraph优化：
  - 符号过滤：一些通用库（比如libc）对性能分析帮助不大；
  - python符号与c++符号整合；


== backtrace机制 -- 抓取python
// set page(margin: (top: 3em, bottom: 1em))
#columns(2)[
  === Python的调用帧本质是个对象
  ```rust
  pub struct PyFrameObject {
      pub ob_base: PyVarObject,
      pub f_back: *PyFrameObject,
      pub f_code: *PyCodeObject,
      pub f_builtins: *PyObject,
      pub f_globals: *PyObject,
      pub f_locals: *PyObject,
      ...
      pub f_lasti: c_int,
      pub f_lineno: c_int,
      ...
      pub f_localsplus: [*PyObject; 1],
  }
  ```
  #colbreak()

  === 抓取PyFrameObj
  - 使用python代码
  ```python
  import traceback
  traceback.print_stack()
  traceback.walk_stack()

  import sys
  sys._getframe()
  ```
  - 借助 PEP 523

  #link("https://peps.python.org/pep-0523/")[PEP 523 – Adding a frame evaluation API to CPython]
  ```C
  PyObject *PyEval_EvalFrameEx(PyFrameObject *frame, int throwflag)
  ```
]

== hook机制 -- hook Python函数

#figure(
  image("imgs/TorchDynamo.png"),
  caption: [借助PEP523 对Python函数进行hook],
)

== hook机制 -- hook c/c++函数
#figure(image("imgs/elf.png", width: 75%))

#figure(image("imgs/linker_reloc.png"))

#grid(
  columns: (1fr, 1fr),
  [#image("imgs/linker_reloc_call.png", width: 75%)], [#image("imgs/linker_reloc_ref.png", width: 75%)],
)#footnote([#link("https://github.com/bytedance/bhook/blob/main/doc/overview.zh-CN.md")])


== inspect 机制 -- python 对象

#figure(
  sourcecode[
    ```python
    import gc
    gc.get_objects()

    tensors = [x for x in gc.get_objects() if type(x) == torch.Tensor]

    modules = [x for x in gc.get_objects() if type(x) == torch.nn.Module]
    ```
  ],
  caption: [使用`gc`实现inspection],
)

#figure(
  sourcecode[
    ```python
    modules = [x for x in gc.get_objects() if type(x) == torch.nn.Module]

    top_modules = [m for m in modules if is_top_module(x)]
    for m in top_modules:
      m.register_forward_hook(hook)
    ```
  ],
  caption: [使用`gc`实现inspection],
)

== inspect 机制 -- c/c++

借助Clang插件: 链接

目前还没有特别好的思路

== tracing机制

tracing的目标：
1.记录函数的调用，输出timeline和call graph等；
2. 记录malloc/free等资源管理函数；

=== Python的tracing
可以分为多个层次，自定向下：
1. PyTorch Module级别：通过前反向hook实现；
2. 函数级别：通过PEP523来实现；

=== C/C++的tracing
- 可以借助plt方式对关键函数进行插桩；

