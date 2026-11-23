import threading

import pytest

import housing_plot_placement as hpp


def make(**kwargs):
    return hpp.HousingPlotPlacement(**kwargs)


def item(h, item_id, size, template=None, **kwargs):
    h.acquire(item_id, template or item_id, size=size, **kwargs)
    return item_id


def test_rotated_long_item_near_a_wall_fits_the_plot():
    h = make()
    item(h, "shelf", (6, 1))
    out = h.place("p1", "shelf", 8.8, 5, rotation=90)
    assert out["rotation"] == 90
    assert h.plot("p1")["items"][0]["item_id"] == "shelf"


def test_unrotated_item_crossing_the_plot_edge_is_rejected():
    h = make()
    item(h, "sofa", (2, 2))
    with pytest.raises(hpp.HousingError):
        h.place("p1", "sofa", 9.5, 5)
    assert "sofa" in h.inventory("player")
    assert h.plot("p1")["items"] == []


def test_two_furniture_pieces_cannot_occupy_the_same_cell():
    h = make()
    item(h, "table", (2, 2))
    item(h, "chest", (2, 2))
    h.place("p1", "table", 5, 5)
    with pytest.raises(hpp.HousingError):
        h.place("p1", "chest", 5.5, 5)
    assert "chest" in h.inventory("player")
    assert len(h.plot("p1")["items"]) == 1


def test_failed_placement_leaves_no_half_placed_furniture():
    h = make()
    item(h, "lamp", (1, 1))
    before = h.plot("p1")
    with pytest.raises(hpp.HousingError) as exc:
        h.place("p1", "lamp", 50, 50)
    assert exc.value.code == "HOME_PLACE_PARTIAL"
    assert h.plot("p1") == before
    assert "lamp" in h.inventory("player")


def test_same_instance_cannot_be_placed_twice():
    h = make()
    item(h, "chair", (1, 1))
    h.place("p1", "chair", 2, 2)
    with pytest.raises(hpp.HousingError) as exc:
        h.place("p1", "chair", 4, 4)
    assert exc.value.code == "HOME_ITEM_DUP"


def test_removal_returns_the_same_instance_with_enhancement_and_binding():
    h = make()
    item(h, "throne", (2, 2), enhance=3, bound=True)
    h.place("p1", "throne", 3, 3)
    with pytest.raises(hpp.HousingError) as exc:
        h.remove("p1", "throne", as_template=True)
    assert exc.value.code == "HOME_RECYCLE_LOSS"
    assert h.plot("p1")["items"][0]["item_id"] == "throne"
    out = h.remove("p1", "throne")
    assert out["enhance"] == 3
    assert out["bound"] is True
    assert out["item_id"] == "throne"


def test_removed_furniture_returns_to_inventory_without_a_template_copy():
    h = make()
    item(h, "desk", (2, 1), enhance=1, bound=True)
    h.place("p1", "desk", 3, 3)
    assert "desk" not in h.inventory("player")
    h.remove("p1", "desk")
    assert "desk" in h.inventory("player")
    assert h.plot("p1")["items"] == []


def test_rotation_is_saved_with_the_placement():
    h = make()
    item(h, "cabinet", (1, 3))
    h.place("p1", "cabinet", 5, 5, rotation=90)
    assert h.plot("p1")["items"][0]["rotation"] == 90
    h.move("p1", "cabinet", 6, 5, rotation=180)
    assert h.plot("p1")["items"][0]["rotation"] == 180


def test_colliding_move_keeps_the_original_position():
    h = make()
    item(h, "bed", (3, 2))
    item(h, "wardrobe", (2, 2))
    h.place("p1", "bed", 3, 3)
    h.place("p1", "wardrobe", 7, 7)
    with pytest.raises(hpp.HousingError):
        h.move("p1", "wardrobe", 3, 3)
    positions = {row["item_id"]: (row["x"], row["y"])
                 for row in h.plot("p1")["items"]}
    assert positions["wardrobe"] == (7, 7)
    assert positions["bed"] == (3, 3)


def test_undo_restores_the_previous_position_after_a_move():
    h = make()
    item(h, "bed", (2, 2))
    h.place("p1", "bed", 3, 3)
    h.move("p1", "bed", 6, 6)
    assert h.plot("p1")["items"][0]["x"] == 6
    h.undo("p1")
    assert h.plot("p1")["items"][0]["x"] == 3
    assert h.plot("p1")["items"][0]["y"] == 3


def test_visitor_cannot_move_owner_furniture_without_permission():
    h = make()
    item(h, "rug", (2, 2))
    h.place("p1", "rug", 3, 3)
    with pytest.raises(hpp.HousingError):
        h.move_as("visitor", "p1", "rug", 5, 5)
    assert h.plot("p1")["items"][0]["x"] == 3
    h.set_permission("p1", "visitor", can_edit=True)
    out = h.move_as("visitor", "p1", "rug", 5, 5)
    assert out["x"] == 5
    h.undo("p1")
    assert h.plot("p1")["items"][0]["x"] == 3


def test_partition_cannot_be_added_through_existing_furniture():
    h = make()
    item(h, "bookshelf", (2, 2))
    h.place("p1", "bookshelf", 4, 4)
    with pytest.raises(hpp.HousingError):
        h.add_partition("p1", 4, 4, 2, 2)
    assert h.plot("p1")["partitions"] == []


def test_expanded_cells_are_usable_and_keep_existing_permissions():
    h = make()
    item(h, "statue", (2, 2))
    h.set_permission("p1", "visitor", can_edit=True)
    with pytest.raises(hpp.HousingError):
        h.place("p1", "statue", 15, 15)
    h.expand("p1", width=20, height=20)
    h.place("p1", "statue", 15, 15)
    assert h.plot("p1")["items"][0]["x"] == 15
    out = h.move_as("visitor", "p1", "statue", 16, 16)
    assert out["x"] == 16


def test_blueprint_copy_skips_limited_furniture():
    h = make()
    item(h, "chair", (1, 1), template="wood-chair")
    item(h, "throne", (1, 1), template="limited-throne")
    h.place("p1", "chair", 1, 1)
    h.place("p1", "throne", 3, 3)
    out = h.copy_layout("p1", "p2", allowed_templates={"wood-chair"})
    templates = [row["template"] for row in h.plot("p2")["items"]]
    assert templates == ["wood-chair"]
    assert out["copied"] == 1
    assert out["skipped"] == ["limited-throne"]


def test_blueprint_copy_preserves_position_and_rotation():
    h = make()
    item(h, "bench", (3, 1), template="wood-bench")
    h.place("p1", "bench", 5, 5, rotation=90)
    h.copy_layout("p1", "p2", allowed_templates={"wood-bench"})
    copied = h.plot("p2")["items"][0]
    assert (copied["x"], copied["y"]) == (5, 5)
    assert copied["rotation"] == 90


def test_diagonally_rotated_furniture_cannot_cross_the_plot_wall():
    h = make()
    item(h, "cabinet", (4, 1))
    before = h.plot("p1")
    with pytest.raises(hpp.HousingError) as exc:
        h.place("p1", "cabinet", 9, 5, rotation=45)
    assert exc.value.code == "HOME_PLACE_PARTIAL"
    assert h.plot("p1") == before
    assert "cabinet" in h.inventory("player")


def test_concurrent_placement_of_the_same_instance_has_one_owner():
    h = make()
    item(h, "chair", (1, 1))
    outcomes = []

    def place():
        try:
            h.place("p1", "chair", 5, 5)
            outcomes.append("placed")
        except hpp.HousingError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=place) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["HOME_ITEM_DUP", "placed"]
    assert "chair" not in h.inventory("player")
    assert len(h.plot("p1")["items"]) == 1


def test_undoing_removal_moves_the_same_instance_back_without_duplication():
    h = make()
    item(h, "desk", (2, 1), enhance=2, bound=True)
    h.place("p1", "desk", 3, 3)
    h.remove("p1", "desk")
    h.undo("p1")

    assert "desk" not in h.inventory("player")
    placements = h.plot("p1")["items"]
    assert len(placements) == 1
    assert placements[0]["enhance"] == 2
    assert placements[0]["bound"] is True


def test_failed_blueprint_copy_does_not_add_any_furniture():
    h = make()
    item(h, "bench-a", (2, 2), template="wood-bench")
    item(h, "bench-b", (2, 2), template="wood-bench")
    h.place("src", "bench-a", 3, 3)
    h.place("src", "bench-b", 7, 7)
    h.copy_layout("src", "dst", allowed_templates={"wood-bench"})
    before = h.plot("dst")

    with pytest.raises(hpp.HousingError) as exc:
        h.copy_layout("src", "dst", allowed_templates={"wood-bench"})
    assert exc.value.code == "HOME_PLACE_PARTIAL"
    assert h.plot("dst") == before
