# Import torch inspection functions
# Note: This loads the torch.py module immediately, but PyTorch itself
# is only imported when these functions are actually called (lazy import).
# This allows probing to be used without PyTorch installed, and torch-specific
# features only fail if explicitly invoked.
from .torch import get_torch_modules
from .torch import get_torch_tensors
from .torch import get_torch_optimizers

def get_dict():
    return {
        "int": 1,
        "float": 1.0,
        "str": "str",
    }
    
def get_list():
    return [
        1,
        1.0,
        "str",
    ]
    
def get_tuple():
    return (
        1,
        1.0,
        "str",
    )
    
def get_set():
    return {
        1,
        1.0,
        "str",
    }
    
def get_dict_list():
    return [
        {
            "int": 1,
            "float": 1.0,
            "str": "str",
        },
        {
            "int": 2,
            "float": 2.0,
            "str": "str2",
        },
    ]