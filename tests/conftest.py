import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def open_file(name, mode="rb"):
    with open(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def control_record_blf():
    yield from open_file("data/control_record.blf")


@pytest.fixture
def bad_control_record_blf():
    yield from open_file("data/bad_control_record.blf")


@pytest.fixture
def invalid_control_record_blf():
    yield from open_file("data/invalid_control_record.blf")


@pytest.fixture
def dummy_blf():
    yield from open_file("data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf")


@pytest.fixture
def dummy_container():
    yield from open_file(
        "data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms"
    )
