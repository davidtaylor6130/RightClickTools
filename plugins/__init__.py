from importlib import import_module
from pathlib import Path
from typing import Dict

def discover_plugins(base_dir: Path) -> Dict[str, object]:
    tools_dir = (base_dir / "tools").resolve()
    results: Dict[str, object] = {}
    for py in sorted(tools_dir.glob("*_tool.py")):
        mod_name = f"tools.{py.stem}"
        mod = import_module(mod_name)
        plugin = getattr(mod, "PLUGIN", None)
        if plugin and getattr(plugin, "key", None):
            results[plugin.key] = plugin
    return results