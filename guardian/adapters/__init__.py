"""Ecosystem implementations; downstream modules consume only shared models."""


def adapters():
    from guardian.adapters.cargo import CargoAdapter
    from guardian.adapters.container import ContainerAdapter
    from guardian.adapters.pypi import PypiAdapter

    return [CargoAdapter(), PypiAdapter(), ContainerAdapter()]
