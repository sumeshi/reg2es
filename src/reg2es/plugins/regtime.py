# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; continue descendant traversal
# after key metadata failures and report diagnostic stages.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Opt-in: produces a timeline of every key's last modification date."""

    __REGHIVE__ = "ALL"
    __DEFAULT_ENABLED__ = False

    def run(self):
        key = self.reg.root()

        yield from self.dump(key)

    def dump(self, key):
        # Match the common runner's Exception-based continue policy, including
        # resource/programming exceptions. BaseException interruptions escape.
        try:
            res = PluginResult(key=key)
        except Exception as exc:
            # A key's metadata can be unreadable even when its children are
            # enumerable.  Report this record and still visit those children
            # under the continue policy.
            try:
                key_path = key.path()
            except Exception:
                key_path = "<unreadable>"
            self.record_error(key_path, None, exc, stage="metadata")
        else:
            key_path = res.path
            yield res

        try:
            subkeys = iter(key.subkeys())
        except Exception as exc:
            self.record_error(key_path, None, exc, stage="subkeys")
            return

        while True:
            try:
                subkey = next(subkeys)
            except StopIteration:
                return
            except Exception as exc:
                # Enumeration can fail after yielding some children.  Its
                # remaining entries are unknown, but the caller can still
                # visit this key's siblings.
                self.record_error(key_path, None, exc, stage="subkeys")
                return

            # Keep child execution outside the enumeration exception handler
            # so strict-policy errors are not reported a second time here.
            yield from self.dump(subkey)
