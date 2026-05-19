hooks = {}


def is_true(value):
    if value in ["TRUE", "True", "true", "1", "YES", "Yes", "yes", "ON", "On", "on"]:
        return True
    return False


def optimizer_step_post_hook(optimizer, *args, **kwargs):
    global hooks
    if optimizer not in hooks:
        hooks[optimizer] = True
        from probing.profiling.torch import next_step
        next_step()

def collective_hook():

    import os
    enble = os.getenv("PB_COLL_TRACE", "False") # set to True to enable collective profiling

    if is_true(enble):
        from group_cc_hook import run_daemon, stop_daemon

        # Start the monitoring daemon
        run_daemon()

def init():
    from torch.optim.optimizer import register_optimizer_step_post_hook

    register_optimizer_step_post_hook(optimizer_step_post_hook)

    collective_hook()


def deinit():
    from probing.profiling.torch import uninstall_hooks

    uninstall_hooks()
