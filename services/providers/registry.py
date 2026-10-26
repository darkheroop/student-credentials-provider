"""
Provider adapter registry for Student Credentials Provider.
"""

from services.providers.base import BaseProviderAdapter
from services.providers.md5decrypt import Md5DecryptAdapter

_REGISTRY: dict[str, type[BaseProviderAdapter]] = {
    "md5decrypt": Md5DecryptAdapter,
}


def get_provider_adapter(provider_name: str) -> BaseProviderAdapter:
    """Retrieve an initialized provider adapter instance by name."""
    name_clean = str(provider_name).strip().lower()
    adapter_cls = _REGISTRY.get(name_clean)
    if not adapter_cls:
        # Fall back to default MD5Decrypt adapter
        adapter_cls = Md5DecryptAdapter
    return adapter_cls()


def register_provider(provider_name: str, adapter_cls: type[BaseProviderAdapter]):
    """Register a new custom provider adapter."""
    _REGISTRY[provider_name.strip().lower()] = adapter_cls
