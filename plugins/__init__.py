"""Plugin discovery utilities."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Dict


def discover_plugins(base_dir: Path) -> Dict[str, object]:
    """Discover and import plugin modules from the ``tools`` directory.

    The original implementation attempted to import modules using the
    ``import_module`` API with names derived from filenames. This approach
    fails when filenames contain characters that are not valid in module
    identifiers (for example ``encrypt-Decrypt_tool.py``). When such a file
    exists, the import would raise ``ModuleNotFoundError`` and prevent *all*
    plugins from loading, leaving the GUI blank.

    To make discovery robust, modules are now loaded directly from their
    file paths using :func:`importlib.util.spec_from_file_location`. Any
    exceptions during import are caught so that a single faulty plugin does
    not stop the application from loading the remaining ones.
    """

    tools_dir = (base_dir / "tools").resolve()
    results: Dict[str, object] = {}
    for py in sorted(tools_dir.glob("*_tool.py")):
        spec = spec_from_file_location(py.stem, py)
        if spec and spec.loader:
            module = module_from_spec(spec)
            try:
                spec.loader.exec_module(module)  # type: ignore[union-attr]
            except Exception:
                # Skip modules that fail to import.
                continue
            plugin = getattr(module, "PLUGIN", None)
            if plugin and getattr(plugin, "key", None):
                results[plugin.key] = plugin
    return results
