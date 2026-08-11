"""Small, conservative common OBIS catalogue used after association discovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CatalogueEntry:
    class_id: int
    logical_name: str
    attributes: tuple[int, ...]
    description: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


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


def catalogue_names() -> tuple[str, ...]:
    return ("common",)
