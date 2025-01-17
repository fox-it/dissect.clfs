from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with absolute_path(name).open(mode) as f:
        yield f


@pytest.fixture
def control_record_blf() -> Iterator[BinaryIO]:
    yield from open_file("data/control_record.blf")


@pytest.fixture
def bad_control_record_blf() -> Iterator[BinaryIO]:
    yield from open_file("data/bad_control_record.blf")


@pytest.fixture
def invalid_control_record_blf() -> Iterator[BinaryIO]:
    yield from open_file("data/invalid_control_record.blf")


@pytest.fixture
def dummy_blf() -> Iterator[BinaryIO]:
    yield from open_file("data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf")


@pytest.fixture
def dummy_container() -> Iterator[BinaryIO]:
    yield from open_file(
        "data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms"
    )
