class HousingError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class HousingPlotPlacement:
    """Plot bounds, rotated collision checks and furniture instance ownership."""

    def __init__(self, *, width=10, height=10, owner="player"):
        self.width = width
        self.height = height
        self.owner = owner

    def acquire(self, item_id, template, *, owner="player", enhance=0,
                bound=False, size=(1, 1)):
        raise NotImplementedError

    def inventory(self, owner=None):
        raise NotImplementedError

    def place(self, plot_id, item_id, x, y, *, rotation=0):
        raise NotImplementedError

    def move(self, plot_id, item_id, x, y, *, rotation=0):
        raise NotImplementedError

    def remove(self, plot_id, item_id, *, as_template=False):
        raise NotImplementedError

    def plot(self, plot_id):
        raise NotImplementedError

    def undo(self, plot_id):
        raise NotImplementedError

    def set_permission(self, plot_id, visitor, can_edit=True):
        raise NotImplementedError

    def move_as(self, actor, plot_id, item_id, x, y, *, rotation=0):
        raise NotImplementedError

    def expand(self, plot_id, *, width, height):
        raise NotImplementedError

    def add_partition(self, plot_id, x, y, w, h):
        raise NotImplementedError

    def copy_layout(self, source_plot, target_plot, allowed_templates):
        raise NotImplementedError
