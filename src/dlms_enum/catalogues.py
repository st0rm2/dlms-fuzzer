"""Small, conservative common OBIS catalogue used after association discovery."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogueEntry:
    class_id: int
    logical_name: str
    attributes: tuple[int, ...]
    description: str
    provider: str = "common"
    rule: str = "fixed_known_object"
    confidence: str = "standard"

# The catalogue deliberately contains common identity and instantaneous/billing
# objects, not an exhaustive OBIS Cartesian product. An absent object normally
# produces an explicit DLMS error and is retained in the report as such.
COMMON_OBIS: tuple[CatalogueEntry, ...] = (
    CatalogueEntry(1, "0.0.42.0.0.255", (2,), "Logical device name"),
    CatalogueEntry(1, "0.0.96.1.0.255", (2,), "Meter serial number"),
    CatalogueEntry(1, "0.0.96.1.1.255", (2,), "Meter serial number (alternate)"),
    CatalogueEntry(1, "1.0.0.2.0.255", (2,), "Firmware identifier"),
    CatalogueEntry(8, "0.0.1.0.0.255", (2, 3, 4), "Clock"),
    CatalogueEntry(17, "0.0.41.0.0.255", (2,), "SAP assignment"),
    CatalogueEntry(3, "1.0.1.8.0.255", (2, 3), "Active energy import total"),
    CatalogueEntry(3, "1.0.2.8.0.255", (2, 3), "Active energy export total"),
    CatalogueEntry(3, "1.0.1.7.0.255", (2, 3), "Active power import"),
    CatalogueEntry(3, "1.0.2.7.0.255", (2, 3), "Active power export"),
    CatalogueEntry(3, "1.0.32.7.0.255", (2, 3), "Voltage L1"),
    CatalogueEntry(3, "1.0.52.7.0.255", (2, 3), "Voltage L2"),
    CatalogueEntry(3, "1.0.72.7.0.255", (2, 3), "Voltage L3"),
    CatalogueEntry(3, "1.0.31.7.0.255", (2, 3), "Current L1"),
    CatalogueEntry(3, "1.0.51.7.0.255", (2, 3), "Current L2"),
    CatalogueEntry(3, "1.0.71.7.0.255", (2, 3), "Current L3"),
    CatalogueEntry(3, "1.0.14.7.0.255", (2, 3), "Frequency"),
)


SECURITY_SETUP_CANDIDATES: tuple[CatalogueEntry, ...] = tuple(
    CatalogueEntry(
        64,
        f"0.0.43.0.{instance}.255",
        (2, 3, 4, 5),
        f"Security Setup candidate #{instance}",
        provider="security",
        rule="standard_security_setup_instance_range_0_15",
        confidence="standard_template",
    )
    for instance in range(16)
)


FIRMWARE_UPDATE_CANDIDATES: tuple[CatalogueEntry, ...] = (
    CatalogueEntry(
        18,
        "0.0.44.0.0.255",
        (2, 5, 6),
        "Image Transfer candidate",
        provider="firmware",
        rule="standard_image_transfer_logical_name",
        confidence="standard_template",
    ),
)


CANDIDATE_PROVIDERS: dict[str, tuple[CatalogueEntry, ...]] = {
    "common": COMMON_OBIS,
    "security": SECURITY_SETUP_CANDIDATES,
    "firmware": FIRMWARE_UPDATE_CANDIDATES,
}


def bounded_candidates(
    providers: tuple[str, ...],
    user_candidates: tuple[CatalogueEntry, ...],
    request_limit: int,
    *,
    excluded_objects: set[tuple[int, str]] | None = None,
) -> tuple[tuple[CatalogueEntry, ...], dict[str, object]]:
    """Return deterministic, deduplicated inferred GET targets within a budget."""

    selected: list[CatalogueEntry] = []
    seen: set[tuple[int, str, int]] = set()
    excluded_objects = excluded_objects or set()
    available = 0
    excluded = 0
    provider_counts: dict[str, int] = {}
    # Exact operator-supplied targets take priority over generic templates when
    # the shared request limit is smaller than the available candidate set.
    sources = list(user_candidates) + [
        entry
        for provider in providers
        for entry in CANDIDATE_PROVIDERS[provider]
    ]
    for entry in sources:
        for attribute_id in entry.attributes:
            key = (entry.class_id, entry.logical_name, attribute_id)
            if key in seen:
                continue
            seen.add(key)
            if (entry.class_id, entry.logical_name) in excluded_objects:
                excluded += 1
                continue
            available += 1
            if len(selected) >= request_limit:
                continue
            selected.append(
                CatalogueEntry(
                    entry.class_id,
                    entry.logical_name,
                    (attribute_id,),
                    entry.description,
                    provider=entry.provider,
                    rule=entry.rule,
                    confidence=entry.confidence,
                )
            )
            provider_counts[entry.provider] = provider_counts.get(entry.provider, 0) + 1
    return tuple(selected), {
        "providers": list(providers) + (["user"] if user_candidates else []),
        "request_limit": request_limit,
        "available_targets": available,
        "selected_targets": len(selected),
        "truncated_targets": max(0, available - len(selected)),
        "excluded_association_targets": excluded,
        "selected_by_provider": provider_counts,
    }
