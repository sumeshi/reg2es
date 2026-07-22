# coding: utf-8
"""Reg2es model — plugin-driven Windows Registry to dict pipeline.

Responsibilities:
  - deterministic plugin discovery from reg2es.plugins
  - hive detection via Registry.Registry.hive_type() and filename fallback
  - __REGHIVE__ str / list / "ALL" matching
  - dataset grouping by hive type, plugin -> declared hive order execution
  - PluginResult -> ECS-compliant document conversion
  - chunk_size-based List[dict] generation
  - parser / file resource lifecycle (close / context manager)
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import re
import shutil
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

from Registry import Registry, RegistryLog, RegistryParse

from reg2es.plugins import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hive type mapping
# ---------------------------------------------------------------------------

# Registry.Registry.hive_type() returns a HiveType enum whose .value is a
# lowercase filename string (e.g. "ntuser.dat", "sam").  We map those to the
# canonical uppercase names used in __REGHIVE__.
_HIVETYPE_TO_NAME: Dict[str, str] = {
    "ntuser.dat": "NTUSER.DAT",
    "sam": "SAM",
    "security": "SECURITY",
    "software": "SOFTWARE",
    "system": "SYSTEM",
    "usrclass.dat": "UsrClass.DAT",
    "bcd": "BCD",
    "components": "COMPONENTS",
    "default": "DEFAULT",
    "schema.dat": "SCHEMA",
    "settings.dat": "SETTINGS",
}

# Filename-based fallback.  Only exact names and common backup suffixes match;
# arbitrary substrings such as ``SAMPLE.bin`` must not be detected as SAM.
_FILENAME_HIVE_PATTERNS: Dict[str, str] = {
    "NTUSER.DAT": "NTUSER.DAT",
    "NTUSER": "NTUSER.DAT",
    "SAM": "SAM",
    "SECURITY": "SECURITY",
    "SOFTWARE": "SOFTWARE",
    "SYSTEM": "SYSTEM",
    "USRCLASS.DAT": "UsrClass.DAT",
    "USRCLASS": "UsrClass.DAT",
    "BCD": "BCD",
}

_TRANSACTION_LOG_SUFFIXES = (".LOG", ".LOG1", ".LOG2")


class RegistryRecoveryError(RuntimeError):
    """Raised when a dirty registry hive cannot be safely recovered."""


def is_transaction_log(path: Path) -> bool:
    """Return whether *path* is a registry transaction log, ignoring case."""
    return path.name.upper().endswith(_TRANSACTION_LOG_SUFFIXES)


_REGF_MAGIC = b"regf"


def looks_like_registry_hive(path: Path) -> bool:
    """Return whether *path* starts with the REGF magic of a registry hive.

    Directory scans can pick up unrelated files (previous JSON exports, thumbs,
    etc.).  Those are not registry hives and must be skipped instead of aborting
    the whole run when the REGF header cannot be parsed.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _REGF_MAGIC
    except OSError:
        return False


def _find_transaction_logs(primary_path: Path) -> List[Path]:
    """Find transaction logs next to a primary hive without case assumptions."""
    expected = {
        f"{primary_path.name}.LOG1".casefold(),
        f"{primary_path.name}.LOG2".casefold(),
    }
    try:
        siblings = primary_path.parent.iterdir()
    except OSError as exc:
        raise RegistryRecoveryError(
            f"Cannot inspect transaction logs for '{primary_path}': {exc}"
        ) from exc
    return sorted(
        (
            item
            for item in siblings
            if item.is_file() and item.name.casefold() in expected
        ),
        key=lambda item: item.name.casefold(),
    )


def _primary_recovery_required(primary_path: Path) -> bool:
    """Read the REGF header and report whether header or data recovery is needed."""
    try:
        with primary_path.open("rb") as primary:
            header = primary.read(512)
        status = RegistryParse.REGFBlock(header, 0, False).recovery_required()
    except Exception as exc:
        raise RegistryRecoveryError(
            f"Cannot inspect registry hive '{primary_path}': {exc}"
        ) from exc
    return bool(status.recover_header or status.recover_data)


def _prepare_registry_hive(primary_path: Path) -> Tuple[Path, Optional[dict]]:
    """Recover a dirty hive into a temporary copy and return its provenance."""
    if is_transaction_log(primary_path):
        raise RegistryRecoveryError(
            f"Transaction log '{primary_path}' cannot be used as a primary hive"
        )

    logs = _find_transaction_logs(primary_path)
    if not _primary_recovery_required(primary_path):
        return primary_path, None
    if not logs:
        raise RegistryRecoveryError(
            f"Registry hive '{primary_path}' is dirty but no .LOG1/.LOG2 was found"
        )

    temporary = tempfile.NamedTemporaryFile(
        prefix="reg2es-recovered-", suffix=".hive", delete=False
    )
    temporary_path = Path(temporary.name)
    temporary.close()
    try:
        shutil.copyfile(primary_path, temporary_path)
        with temporary_path.open("r+b") as recovered:
            try:
                parsed_logs = []
                for path in logs:
                    recovered.seek(0)
                    parsed_logs.append(RegistryLog.RegistryLog(recovered, str(path)))
            except RegistryParse.NotSupportedException as exc:
                raise RegistryRecoveryError(
                    f"Unsupported transaction log for '{primary_path}': {exc}. "
                    "Recover the hive externally (for example with rla.exe) "
                    "and provide the recovered hive to reg2es"
                ) from exc
            except Exception as exc:
                raise RegistryRecoveryError(
                    f"Cannot parse transaction log for '{primary_path}': {exc}"
                ) from exc

            eligible = [log for log in parsed_logs if log.is_eligible_log()]
            if not eligible:
                raise RegistryRecoveryError(
                    f"Registry hive '{primary_path}' is dirty but has no eligible log"
                )
            if len(eligible) == 2 and not eligible[0].is_starting_log(eligible[1]):
                eligible.reverse()

            try:
                last_sequence = eligible[0].recover_hive()
                if last_sequence is None:
                    raise RegistryRecoveryError(
                        f"Transaction log did not recover dirty hive '{primary_path}'"
                    )
                applied_paths = [logs[parsed_logs.index(eligible[0])]]
                for continuation in eligible[1:]:
                    continuation.reload_primary_regf()
                    last_sequence = continuation.recover_hive_continue(
                        (last_sequence + 1) & 0xFFFFFFFF
                    )
                    if last_sequence is None:
                        raise RegistryRecoveryError(
                            f"Transaction log sequence is discontinuous for '{primary_path}'"
                        )
                    applied_paths.append(logs[parsed_logs.index(continuation)])
            except RegistryRecoveryError:
                raise
            except Exception as exc:
                raise RegistryRecoveryError(
                    f"Failed to recover registry hive '{primary_path}': {exc}"
                ) from exc

        if _primary_recovery_required(temporary_path):
            raise RegistryRecoveryError(
                f"Recovered registry hive '{primary_path}' is still dirty"
            )

        return temporary_path, {
            "applied": True,
            "method": "python-registry.RegistryLog",
            "logs": [str(path.resolve()) for path in applied_paths],
        }
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def detect_hive_type(reg: Registry.Registry, file_path: Path) -> str:
    """Return canonical hive name using hive_type() first, filename fallback.

    Args:
        reg: Opened Registry object.
        file_path: Path to the hive file (used for fallback).

    Returns:
        Canonical hive name (e.g. "SOFTWARE", "NTUSER.DAT") or "UNKNOWN".
    """
    if is_transaction_log(file_path):
        return "UNKNOWN"

    try:
        ht = reg.hive_type()
        name = _HIVETYPE_TO_NAME.get(ht.value)
        if name:
            return name
    except Exception:
        pass

    # Fallback: filename matching (case-insensitive).
    upper_name = file_path.name.upper()
    for pattern, canonical in _FILENAME_HIVE_PATTERNS.items():
        if upper_name == pattern or re.match(
            rf"^{re.escape(pattern)}[._-]", upper_name
        ):
            return canonical

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------


def discover_plugins() -> List[Tuple[str, Type[BasePlugin]]]:
    """Discover all Plugin classes in reg2es.plugins.

    Returns a deterministically ordered list of (module_name, PluginClass).
    Modules are sorted by filename to ensure reproducible ordering.
    """
    import reg2es.plugins as plugins_pkg

    result: List[Tuple[str, Type[BasePlugin]]] = []
    for _importer, module_name, is_pkg in pkgutil.iter_modules(
        plugins_pkg.__path__, prefix=""
    ):
        if is_pkg:
            continue
        mod = importlib.import_module(f"reg2es.plugins.{module_name}")

        plugin_cls = getattr(mod, "Plugin", None)
        if plugin_cls is None or not (
            isinstance(plugin_cls, type) and issubclass(plugin_cls, BasePlugin)
        ):
            continue
        result.append((module_name, plugin_cls))

    # Deterministic order: sort by module name.
    result.sort(key=lambda x: x[0])
    return result


def resolve_plugin_names(
    names: Optional[Sequence[str]],
    all_plugins: List[Tuple[str, Type[BasePlugin]]],
) -> List[Tuple[str, Type[BasePlugin]]]:
    """Validate and resolve plugin names against discovered plugins.

    Args:
        names: Requested plugin names (module basenames), or None for the
            default-enabled plugins.
        all_plugins: Full discovered plugin list.

    Returns:
        Filtered list in the same order as *all_plugins*.

    Raises:
        ValueError: If a requested name does not match any discovered plugin.
    """
    if names is None:
        return [
            (name, cls)
            for name, cls in all_plugins
            if getattr(cls, "__DEFAULT_ENABLED__", True)
        ]

    lookup = {name: cls for name, cls in all_plugins}
    resolved: List[Tuple[str, Type[BasePlugin]]] = []
    for name in names:
        cls = lookup.get(name)
        if cls is None:
            available = sorted(lookup.keys())
            raise ValueError(f"Unknown plugin '{name}'. Available plugins: {available}")
        resolved.append((name, cls))
    return resolved


# ---------------------------------------------------------------------------
# Hive matching
# ---------------------------------------------------------------------------


def plugin_matches_hive(plugin_cls: Type[BasePlugin], hive_name: str) -> bool:
    """Check whether a plugin is compatible with the given hive.

    __REGHIVE__ can be:
      - "ALL": matches any hive
      - a str: exact match (case-insensitive)
      - a list of str: any element matches (case-insensitive)
    """
    reghive = getattr(plugin_cls, "__REGHIVE__", None)
    if reghive is None:
        return False
    if isinstance(reghive, str):
        if reghive.upper() == "ALL":
            return True
        return reghive.upper() == hive_name.upper()
    if isinstance(reghive, (list, tuple)):
        return any(r.upper() == hive_name.upper() for r in reghive)
    return False


# ---------------------------------------------------------------------------
# PluginResult -> document conversion
# ---------------------------------------------------------------------------


def _normalize_value(value: Any) -> Any:
    """Recursively normalize a value for JSON / Elasticsearch safety.

    - bytes -> hex string
    - datetime -> ISO 8601 string
    - enum -> .value
    - tuple -> list
    - dict -> recursively normalize values
    - list -> recursively normalize items
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return _normalize_value(value.value)
    if isinstance(value, dict):
        return {str(k): _normalize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize_value(v) for v in value]
    # int, float, str, bool pass through.
    if isinstance(value, (int, float, str, bool)):
        return value

    # A RegistryValue occasionally appears in upstream plugin custom data.
    # Preserve its actual data rather than stringifying the wrapper object.
    value_method = getattr(value, "value", None)
    if callable(value_method):
        return _normalize_value(value_method())

    # Preserve simple value objects such as tasks.RegistryAction as a
    # structured mapping.  Ignore private implementation details.
    try:
        public_attributes = {
            key: item for key, item in vars(value).items() if not key.startswith("_")
        }
    except TypeError:
        public_attributes = {}
    if public_attributes:
        return _normalize_value(public_attributes)

    raise TypeError(
        f"Unsupported value type for JSON normalization: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def _timestamp_to_iso(value: Any) -> Optional[str]:
    """Convert a positive Unix timestamp to UTC ISO 8601, if valid."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


_ECS_HKLM_HIVES = {
    "BCD",
    "COMPONENTS",
    "SAM",
    "SCHEMA",
    "SECURITY",
    "SETTINGS",
    "SOFTWARE",
    "SYSTEM",
}


def _join_registry_path(*parts: Optional[str]) -> str:
    return "\\".join(part.strip("\\") for part in parts if part)


def _ecs_registry_location(
    hive_name: str, plugin_path: Optional[str]
) -> Tuple[str, str, str]:
    """Map an offline hive path to ECS ``registry.hive/key/path`` fields."""
    relative_path = (plugin_path or "").strip("\\")
    if relative_path == "ROOT":
        relative_path = ""
    elif relative_path.startswith("ROOT\\"):
        relative_path = relative_path[5:]

    if hive_name in _ECS_HKLM_HIVES:
        ecs_hive = "HKLM"
        key = _join_registry_path(hive_name, relative_path)
    elif hive_name == "NTUSER.DAT":
        ecs_hive = "HKCU"
        key = relative_path
    elif hive_name == "UsrClass.DAT":
        ecs_hive = "HKCU"
        key = _join_registry_path("Software\\Classes", relative_path)
    elif hive_name == "DEFAULT":
        ecs_hive = "HKU"
        key = _join_registry_path(".DEFAULT", relative_path)
    else:
        # Keep uncommon/custom hive identifiers useful without inventing a
        # Windows mount point that is not known from the hive file alone.
        ecs_hive = hive_name
        key = relative_path
    return ecs_hive, key, _join_registry_path(ecs_hive, key)


def plugin_result_to_document(
    result: PluginResult,
    plugin_name: str,
    hive_name: str,
    hive_path: str,
    additional_tags: Optional[Sequence[str]] = None,
    recovery: Optional[dict] = None,
) -> dict:
    """Convert a single PluginResult to an ECS-compliant document.

    Preserves all PluginResult fields including custom and value_data.
    """
    # Timestamp: prefer mtime, fallback to btime.
    timestamp = _timestamp_to_iso(result.mtime) or _timestamp_to_iso(result.btime)

    registry_hive, registry_key, registry_path = _ecs_registry_location(
        hive_name, result.path
    )
    doc: dict = {
        "event": {
            "kind": "event",
            "category": ["registry"],
            "type": ["info"],
            "action": plugin_name,
        },
        "registry": {
            "hive": registry_hive,
            "key": registry_key,
            "path": registry_path,
        },
        "log": {
            "file": {
                "path": (str(Path(hive_path).resolve()) if hive_path != "-" else "-"),
            },
        },
        "tags": list(
            dict.fromkeys(
                ["registry", *(additional_tags or [])],
            )
        ),
        "reg2es": {
            "plugin": {"name": plugin_name},
            "source": {"hive": hive_name, "key_path": result.path},
        },
    }
    if timestamp is not None:
        doc["@timestamp"] = timestamp

    # Value fields.
    if result.value_name is not None:
        normalized_data = _normalize_value(result.value_data)
        doc["registry"]["value"] = result.value_name
        registry_data: dict = {"type": result.value_type}
        if isinstance(result.value_data, bytes):
            registry_data["bytes"] = len(result.value_data)
            registry_data["strings"] = [normalized_data]
        elif isinstance(normalized_data, str):
            registry_data["strings"] = [normalized_data]
        elif isinstance(normalized_data, list) and all(
            isinstance(item, str) for item in normalized_data
        ):
            registry_data["strings"] = normalized_data
        doc["registry"]["data"] = registry_data
        doc["reg2es"]["value_data"] = normalized_data

    # Custom fields (lossless).
    if result.custom:
        doc["reg2es"]["custom"] = _normalize_value(result.custom)

    if recovery is not None:
        doc["reg2es"]["recovery"] = _normalize_value(recovery)

    # Preserve raw plugin timestamps and provide valid ISO forms when possible.
    raw_timestamps = {
        "accessed": result.atime,
        "changed": result.ctime,
        "created": result.btime,
        "modified": result.mtime,
    }
    if any(value not in (None, 0, -1) for value in raw_timestamps.values()):
        doc["reg2es"]["timestamps"] = raw_timestamps
    iso_timestamps = {
        key: converted
        for key, value in raw_timestamps.items()
        if (converted := _timestamp_to_iso(value)) is not None
    }
    if iso_timestamps:
        doc["reg2es"]["timestamp_iso"] = iso_timestamps

    return doc


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------


def _build_hive_dataset(
    input_paths: Sequence[Path],
) -> Dict[str, List[Tuple[Path, Registry.Registry]]]:
    """Group input paths by detected hive type.

    Returns:
        Dict mapping canonical hive name -> list of (path, Registry) tuples.
    """
    dataset: Dict[str, List[Tuple[Path, Registry.Registry]]] = {}
    candidate_paths = [path for path in input_paths if not is_transaction_log(path)]
    primary_paths = []
    for path in candidate_paths:
        if looks_like_registry_hive(path):
            primary_paths.append(path)
        else:
            logger.warning(
                "Skipping '%s': not a registry hive (missing REGF header)", path
            )
    if not primary_paths:
        raise RegistryRecoveryError("No primary registry hive was provided")
    try:
        for path in sorted(primary_paths, key=lambda item: str(item)):
            parser_path, recovery = _prepare_registry_hive(path)
            try:
                reg = Registry.Registry(str(parser_path))
                setattr(reg, "_reg2es_recovery", recovery)
                setattr(
                    reg,
                    "_reg2es_temporary_path",
                    parser_path if parser_path != path else None,
                )
                hive_name = detect_hive_type(reg, path)
                dataset.setdefault(hive_name, []).append((path, reg))
            except Exception:
                if parser_path != path:
                    parser_path.unlink(missing_ok=True)
                raise
    except Exception:
        _close_parsers(dataset)
        raise
    return dataset


def _close_parsers(
    dataset: Dict[str, List[Tuple[Path, Registry.Registry]]],
) -> None:
    """Close all Registry objects in the dataset."""
    # python-registry reads the complete file in its constructor and closes
    # the underlying file immediately.  Clearing references releases its
    # in-memory buffers promptly, including when a generator is closed early.
    for entries in dataset.values():
        for _path, reg in entries:
            temporary_path = _get_registry_metadata(reg, "_reg2es_temporary_path")
            if temporary_path is not None:
                Path(temporary_path).unlink(missing_ok=True)
    dataset.clear()


def _get_registry_metadata(reg: Registry.Registry, attribute: str) -> Any:
    """Return metadata explicitly attached to a Registry object.

    Tests often use ``MagicMock`` objects as stand-ins for python-registry
    parsers.  ``getattr(mock, "missing", None)`` fabricates a child mock
    instead of returning the default, which can then be recursively normalized
    and grow memory without bound.  Reading the instance ``__dict__`` only
    returns attributes that were actually set by ``_build_hive_dataset``.
    """
    try:
        return vars(reg).get(attribute)
    except TypeError:
        return None


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


class Reg2es:
    """Plugin-driven registry parser.

    Args:
        input_paths: One or more paths to registry hive files.
        plugin_names: Optional list of plugin module names to run.
            None means run compatible, default-enabled plugins.
        chunk_size: Number of documents per yielded chunk.
        error_policy: ``"continue"`` (default) logs and skips plugin errors;
            ``"raise"`` re-raises the first exception.
        additional_tags: Extra tags added to every generated document.
    """

    def __init__(
        self,
        input_paths: Union[Path, str, Sequence[Path]],
        plugin_names: Optional[Sequence[str]] = None,
        chunk_size: int = 500,
        error_policy: str = "continue",
        additional_tags: Optional[Sequence[str]] = None,
    ) -> None:
        if error_policy not in ("continue", "raise"):
            raise ValueError(
                "error_policy must be 'continue' or 'raise', " f"got {error_policy!r}"
            )
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be greater than zero, got {chunk_size}")
        if isinstance(input_paths, (str, Path)):
            self.input_paths = [Path(input_paths)]
        else:
            self.input_paths = [Path(path) for path in input_paths]
        self.chunk_size = chunk_size
        self.error_policy = error_policy
        self.additional_tags = [
            tag.strip() for tag in (additional_tags or []) if tag and tag.strip()
        ]

        # Discover and validate plugins once.
        all_plugins = discover_plugins()
        self.plugins = resolve_plugin_names(plugin_names, all_plugins)

    # Context manager -------------------------------------------------

    def close(self) -> None:
        """Close the runner.

        ``python-registry`` closes each input file in its constructor after
        reading it into memory.  Datasets are scoped to ``gen_records()`` and
        cleared in its ``finally`` block, so there is no persistent handle to
        release here.
        """

    def __enter__(self) -> "Reg2es":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # Record generation -----------------------------------------------

    def _execute_plugin(
        self,
        plugin_cls: Type[BasePlugin],
        reg: Registry.Registry,
        hive_name: str,
        hive_path: str,
    ) -> Generator[PluginResult, None, None]:
        """Instantiate and run a single plugin, yielding PluginResults."""
        instance = plugin_cls(reg, logger, hive_name, hive_path)
        yield from instance.run()

    def _iter_documents(self) -> Generator[dict, None, None]:
        """Yield individual documents from all inputs and plugins.

        Processing order:
          1. Plugins are iterated in discovered (module-name) order.
          2. For each plugin, declared __REGHIVE__ order is respected.
             E.g. ["SOFTWARE", "SAM"] means SOFTWARE hives are processed
             before SAM hives.
        The same plugin instance is reused across hives within one dataset to
        support enrichment patterns. Mutable class defaults are copied onto
        that instance so state cannot leak into another dataset.
        """
        dataset = _build_hive_dataset(self.input_paths)
        try:
            for plugin_name, plugin_cls in self.plugins:
                # Determine hive processing order from __REGHIVE__.
                reghive = getattr(plugin_cls, "__REGHIVE__", None)
                if reghive is None:
                    continue
                if isinstance(reghive, str):
                    if reghive.upper() == "ALL":
                        hive_order = sorted(dataset)
                    else:
                        hive_order = [reghive]
                elif isinstance(reghive, (list, tuple)):
                    hive_order = list(reghive)
                else:
                    continue

                # Create a single plugin instance to share across hives
                # (for enrichment patterns like localgroups).
                # We need a dummy reg/logger/hive for __init__; we'll
                # override per-hive below.
                # Use the first available hive's reg for initialization.
                first_reg: Optional[Registry.Registry] = None
                first_hive = ""
                first_path = ""
                for hive_name in hive_order:
                    entries = dataset.get(hive_name, [])
                    if entries:
                        first_path, first_reg = entries[0]
                        first_hive = hive_name
                        break

                if first_reg is None:
                    # None of the declared hives are present in the dataset.
                    continue

                instance = plugin_cls(
                    first_reg,
                    logger,
                    first_hive,
                    str(first_path),
                )

                # Upstream localgroups and gpo keep mutable state on their
                # classes.  Shadow every mutable default on the instance so
                # one dataset (or concurrent runner) cannot contaminate
                # another. localgroups must always start with an empty list,
                # even if external code previously modified its class value.
                for attribute, default in vars(plugin_cls).items():
                    if attribute.startswith("__") or not isinstance(
                        default, (dict, list, set)
                    ):
                        continue
                    if attribute == "user_profile_list":
                        setattr(instance, attribute, [])
                    else:
                        setattr(instance, attribute, deepcopy(default))

                for hive_name in hive_order:
                    if not plugin_matches_hive(plugin_cls, hive_name):
                        continue
                    entries = dataset.get(hive_name, [])
                    for hive_path, reg in entries:
                        # Re-bind the instance to the current hive.
                        instance.reg = reg
                        instance.hive_name = hive_name
                        instance.hive_path = str(hive_path)

                        try:
                            for result in instance.run():
                                doc = plugin_result_to_document(
                                    result,
                                    plugin_name,
                                    hive_name,
                                    str(hive_path),
                                    getattr(self, "additional_tags", None),
                                    _get_registry_metadata(reg, "_reg2es_recovery"),
                                )
                                yield doc
                        except Exception as exc:
                            if self.error_policy == "raise":
                                raise
                            logger.warning(
                                "Plugin '%s' failed on hive '%s' (%s): %s",
                                plugin_name,
                                hive_name,
                                hive_path,
                                exc,
                            )
        finally:
            _close_parsers(dataset)

    def gen_records(self) -> Generator[List[dict], None, None]:
        """Yield fixed-size document chunks, including the final remainder."""
        chunk: List[dict] = []
        documents = self._iter_documents()
        try:
            for document in documents:
                chunk.append(document)
                if len(chunk) == self.chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk
        finally:
            documents.close()

    def gen_chunks(self) -> Generator[List[dict], None, None]:
        """Compatibility alias for the canonical ``gen_records`` API."""
        yield from self.gen_records()
