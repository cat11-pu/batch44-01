import pytest

import asset_hot_reload_watch as ahr


def make(**kwargs):
    return ahr.AssetHotReloadWatch(**kwargs)


def test_changing_a_texture_reloads_dependent_material():
    h = make()
    h.register("tex/a.png", data="old", kind="texture")
    h.register("mat/a.mat", data="mat-old", kind="material", deps=("tex/a.png",))
    material_handle = h.handle("mat/a.mat")
    h.update("tex/a.png", "new")
    h.notify("tex/a.png", now=0)
    h.flush()
    assert h.read("tex/a.png") == "new"
    assert h.handle("mat/a.mat") != material_handle
    assert h.stats()["reloads"] == 2


def test_dependency_group_swap_is_all_or_nothing():
    h = make()
    h.register("tex/a.png", data="tex-old")
    h.register("mat/a.mat", data="mat-old", deps=("tex/a.png",))
    h.update("tex/a.png", "tex-new")
    h.notify("tex/a.png", now=0)
    with pytest.raises(ahr.ReloadError) as exc:
        h.flush(fail_at="mat/a.mat")
    assert exc.value.code == "HOTRELOAD_PARTIAL"
    assert h.read("tex/a.png") == "tex-old"
    assert h.read("mat/a.mat") == "mat-old"


def test_failed_reload_of_a_new_asset_reports_a_lost_asset():
    h = make()
    h.register("tex/new.png", data=None)
    h.notify("tex/new.png", now=0)
    with pytest.raises(ahr.ReloadError) as exc:
        h.flush(fail_at="tex/new.png")
    assert exc.value.code == "HOTRELOAD_LOST"


def test_paths_are_compared_case_insensitively():
    h = make()
    h.register("Assets/Hero.PNG", data="first")
    h.register("assets/hero.png", data="second")
    assert h.stats()["assets"] == 1
    assert h.read("ASSETS/HERO.PNG") == "second"


def test_repeated_changes_within_the_window_are_coalesced():
    h = make(debounce_ms=200)
    h.register("tex/a.png", data="old")
    for tick in range(5):
        h.update("tex/a.png", "new-%d" % tick)
        h.notify("tex/a.png", now=tick * 10)
    h.flush()
    assert h.stats()["reloads"] == 1
    assert h.read("tex/a.png") == "new-4"


def test_forced_reload_inside_the_window_is_a_storm():
    h = make(debounce_ms=200)
    h.register("tex/a.png", data="old")
    h.notify("tex/a.png", now=0)
    with pytest.raises(ahr.ReloadError) as exc:
        h.notify("tex/a.png", now=50, force=True)
    assert exc.value.code == "HOTRELOAD_STORM"


def test_old_handles_become_invalid_after_a_reload():
    h = make()
    h.register("tex/a.png", data="old")
    old = h.handle("tex/a.png")
    h.update("tex/a.png", "new")
    h.notify("tex/a.png", now=0)
    h.flush()
    with pytest.raises(ahr.ReloadError):
        h.resolve(old)
    assert h.resolve(h.handle("tex/a.png")) == "new"


def test_removed_asset_keeps_its_last_valid_data():
    h = make()
    h.register("tex/a.png", data="old")
    h.remove("tex/a.png")
    assert h.read("tex/a.png") == "old"
    assert h.stats()["assets"] == 0


def test_packed_assets_reload_from_the_unpacked_source():
    h = make()
    h.register("tex/packed.png", data="packed-old", packed=True,
               source="disk/tex.png")
    h.set_source("tex/packed.png", "raw-new")
    h.notify("tex/packed.png", now=0)
    h.flush()
    assert h.read("tex/packed.png") == "raw-new"


def test_reload_releases_the_previous_gpu_allocation():
    h = make()
    h.register("tex/a.png", data="old")
    h.register("tex/b.png", data="b")
    assert h.stats()["gpu"] == 2
    h.update("tex/a.png", "new")
    h.notify("tex/a.png", now=0)
    h.flush()
    assert h.stats()["gpu"] == 2


def test_readers_see_old_data_until_the_swap_then_new_data():
    h = make()
    h.register("tex/a.png", data="old")
    h.update("tex/a.png", "new")
    h.notify("tex/a.png", now=0)
    assert h.read("tex/a.png") == "old"
    h.flush()
    assert h.read("tex/a.png") == "new"


def test_log_directory_events_are_ignored():
    h = make()
    h.register("tex/a.png", data="old")
    assert h.notify("logs/watch.log", now=0) is False
    h.flush()
    assert h.stats()["reloads"] == 0


def test_failed_reload_can_be_retried_cleanly():
    h = make()
    h.register("tex/a.png", data="old")
    h.update("tex/a.png", "new")
    h.notify("tex/a.png", now=0)
    with pytest.raises(ahr.ReloadError):
        h.flush(fail_at="tex/a.png")
    assert h.read("tex/a.png") == "old"
    h.flush()
    assert h.read("tex/a.png") == "new"
    assert h.stats()["reloads"] == 1


def test_dependency_cycle_reloads_each_asset_once():
    h = make()
    h.register("a.mat", data="a", deps=("b.mat",))
    h.register("b.mat", data="b", deps=("a.mat",))
    h.update("a.mat", "a2")
    h.notify("a.mat", now=0)
    h.flush()
    assert h.stats()["reloads"] == 2


def test_moving_an_asset_keeps_its_handle_and_data():
    h = make()
    h.register("tex/old.png", data="pixels", uid="tex-1")
    handle = h.handle("tex/old.png")
    h.move("tex/old.png", "tex/new.png")
    assert h.resolve(handle) == "pixels"
    assert h.read("tex/new.png") == "pixels"
    with pytest.raises(ahr.ReloadError):
        h.read("tex/old.png")
