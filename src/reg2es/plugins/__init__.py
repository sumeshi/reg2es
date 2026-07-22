"""Bundled Windows Registry analysis plugins.

The plugin API and implementations are derived from airbus-cert/regrippy
2.0.3 under the Apache License 2.0. See the project README for provenance.
"""

from reg2es.plugins.base import BasePlugin, PluginResult, mactime

__all__ = ["BasePlugin", "PluginResult", "mactime"]
