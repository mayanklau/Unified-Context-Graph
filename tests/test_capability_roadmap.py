from ucg.capabilities import CAPABILITY_ROADMAP


def test_capability_roadmap_has_core_future_areas() -> None:
    areas = {area.name for area in CAPABILITY_ROADMAP}

    assert "Graph Platform Foundation" in areas
    assert "Trust DLP" in areas
    assert "LLM Firewall And AI Security" in areas
    assert all(area.capabilities for area in CAPABILITY_ROADMAP)
