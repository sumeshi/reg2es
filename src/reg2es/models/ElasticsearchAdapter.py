"""Registry-specific raw-value mapping; source values and IDs stay intact."""

from elasticsearch import BadRequestError, NotFoundError


class ElasticsearchAdapter:
    def __init__(self, client):
        self.es = client
        self._value_data_indices = set()

    def prepare_records(self, records, index_name):
        raw_mapping_checked = False
        for record in records:
            if "value_data" in record.get("reg2es", {}) and not raw_mapping_checked:
                self._ensure_value_data_mapping(index_name)
                raw_mapping_checked = True
            yield record

    def prepare_source(self, record):
        return record

    def _ensure_value_data_mapping(self, index_name: str) -> None:
        """Keep arbitrary raw values in _source without parsing or indexing them."""
        if index_name in self._value_data_indices:
            return
        properties = {
            "reg2es": {
                "properties": {"value_data": {"type": "object", "enabled": False}}
            }
        }
        try:
            metadata = self.es.indices.get(
                index=index_name, features=["aliases", "mappings"]
            )
        except NotFoundError:
            try:
                self.es.indices.create(
                    index=index_name, mappings={"properties": properties}
                )
            except BadRequestError as error:
                detail = (
                    error.body.get("error", {}) if isinstance(error.body, dict) else {}
                )
                if (
                    not isinstance(detail, dict)
                    or detail.get("type") != "resource_already_exists_exception"
                ):
                    raise
                metadata = self.es.indices.get(
                    index=index_name, features=["aliases", "mappings"]
                )
            else:
                self._value_data_indices.add(index_name)
                return

        if index_name in metadata:
            concrete_index = index_name
        else:
            aliases = {
                name: info.get("aliases", {}).get(index_name)
                for name, info in metadata.items()
                if index_name in info.get("aliases", {})
            }
            writable = [
                name
                for name, alias in aliases.items()
                if alias.get("is_write_index") is True
            ]
            if len(writable) == 1:
                concrete_index = writable[0]
            elif (
                len(aliases) == 1
                and next(iter(aliases.values())).get("is_write_index") is not False
            ):
                concrete_index = next(iter(aliases))
            else:
                raise RuntimeError(
                    f"Cannot determine one write index for {index_name!r}; "
                    "specify a concrete index or an alias with one write index."
                )

        mapping = metadata[concrete_index].get("mappings", {})
        container = mapping.get("properties", {}).get("reg2es", {})
        raw_mapping = container.get("properties", {}).get("value_data")
        if container.get("enabled") is not False:
            if raw_mapping is not None and raw_mapping.get("enabled") is not False:
                raise RuntimeError(
                    f"Index {concrete_index!r} has an incompatible reg2es.value_data "
                    "mapping; raw values require an object with enabled:false. "
                    "Use a new index with that mapping. Existing mapping was not changed."
                )
            if raw_mapping is None:
                self.es.indices.put_mapping(index=concrete_index, properties=properties)
        # Resolve aliases on every batch so a later write-index change is checked.
        if concrete_index == index_name:
            self._value_data_indices.add(index_name)
