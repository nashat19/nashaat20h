from osintx.providers import registry

def test_registry_discovers_providers():
    found = registry.discover()
    assert "hibp" in found
    assert "username-generic" in found
    assert "phone-local" in found

def test_registry_build_filters_by_category():
    built = registry.build(categories=["phone"])
    assert built
    assert all(p.meta.category == "phone" for p in built)
