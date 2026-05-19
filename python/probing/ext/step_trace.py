import time
from dataclasses import dataclass
from probing.core.table import table


@table
@dataclass
class StepDuration:
    step: int
    duration_ms: float


class StepTracer:
    def __init__(self):
        self.last_time = None
        self.step = 0

    def post_hook(self, optimizer, *args, **kwargs):
        now = time.time()

        if self.last_time is not None:
            duration_ms = (now - self.last_time) * 1000.0
            StepDuration(step=self.step, duration_ms=duration_ms).save()

        self.step += 1
        self.last_time = now


_tracer = StepTracer()


def optimizer_step_post_hook(optimizer, *args, **kwargs):
    _tracer.post_hook(optimizer, *args, **kwargs)


def init():
    from torch.optim.optimizer import register_optimizer_step_post_hook

    register_optimizer_step_post_hook(optimizer_step_post_hook)


def deinit():
    pass
