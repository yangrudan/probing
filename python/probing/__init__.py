from .trace import probe
from .repl import DebugConsole

_ALL_ = [
    "init",
    "probe",
    "DebugConsole",
]

VERSION = "0.2.0"

def init(listen=None):
    """
    Initialize probing by loading the libprobing.so dynamic library.
    
    Args:
        listen (str, optional): Address to listen on for remote connections.
                               Format: '<ip>:<port>', e.g., '127.0.0.1:9922'
    
    Returns:
        The loaded library object.
    
    Raises:
        ImportError: If the library cannot be found or loaded.
    """
    import ctypes
    import os
    import pathlib
    import sys
    
    # Set environment variables if needed
    if listen:
        os.environ["PROBING_PORT"] = listen.split(":")[-1]
    
    # Search paths for the library
    paths = [
        pathlib.Path(sys.executable).parent / "libprobing.so",
        pathlib.Path.cwd() / "libprobing.so",
    ]
    
    # Try loading the library from each path
    for path in paths:
        if path.exists():
            try:
                return ctypes.CDLL(str(path))
            except Exception:
                continue  # Try the next path if loading fails
    
    # If we get here, the library wasn't found or couldn't be loaded
    raise ImportError(
        f"Could not find or load libprobing.so. Searched in: {', '.join(str(p) for p in paths)}"
    )