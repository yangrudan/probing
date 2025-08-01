def foo():
    bar()
    
def bar():
    import probing
    stacks = probing._get_python_stacks()
    frames = probing._get_python_frames()
    
    import traceback
    tb = traceback.extract_stack()
    tb.reverse()
    print("call stacks with traceback:")
    for frame in tb:
        if frame.name in ["foo", "bar"]:
            print(f"\tFrame: {frame.name} in {frame.filename}:{frame.lineno}")
    print("call stacks with probing stacks:")
    for frame in stacks:
        if frame["func"] in ["foo", "bar"]:
            print(f"\tFrame: {frame['func']} in {frame['file']}:{frame['lineno']}")
    print("call stacks with probing frames:")
    for frame in frames:
        if frame["func"] in ["foo", "bar"]:
            print(f"\tFrame: {frame['func']} in {frame['file']}:{frame['lineno']}")

def test_python_tracer():
    import probing
    
    probing.enable_tracer()
    
    foo()