"""
tests/test_event_bus.py
-----------------------------------------------------------------------------
Unit tests for the Layer 0 Pub/Sub Event Bus (scripts/9_utilities/event_bus.py).
-----------------------------------------------------------------------------
"""

import threading
import pytest
from event_bus import (
    EventBus,
    get_event_bus,
    subscribe,
    unsubscribe,
    publish,
    clear_subscribers,
)


@pytest.fixture(autouse=True)
def clean_bus():
    """Ensure global event bus is cleared before and after each test."""
    clear_subscribers()
    yield
    clear_subscribers()


def test_event_bus_subscribe_and_publish():
    bus = EventBus()
    received = []

    def handler(payload):
        received.append(payload)

    bus.subscribe("alert", handler)
    count = bus.publish("alert", {"ip": "1.2.3.4", "score": 0.99})

    assert count == 1
    assert len(received) == 1
    assert received[0]["ip"] == "1.2.3.4"


def test_event_bus_multiple_subscribers():
    bus = EventBus()
    res1 = []
    res2 = []

    bus.subscribe("ping", lambda msg: res1.append(msg))
    bus.subscribe("ping", lambda msg: res2.append(msg))

    count = bus.publish("ping", "hello")
    assert count == 2
    assert res1 == ["hello"]
    assert res2 == ["hello"]


def test_event_bus_unsubscribe():
    bus = EventBus()
    res = []

    def handler(data):
        res.append(data)

    bus.subscribe("tick", handler)
    assert bus.publish("tick", 1) == 1

    removed = bus.unsubscribe("tick", handler)
    assert removed is True
    assert bus.publish("tick", 2) == 0
    assert res == [1]


def test_event_bus_exception_isolation():
    bus = EventBus()
    good_results = []

    def faulty_handler(data):
        raise ValueError("Boom!")

    def good_handler(data):
        good_results.append(data)

    bus.subscribe("ev", faulty_handler)
    bus.subscribe("ev", good_handler)

    # Faulty handler raises, but good handler still receives event
    count = bus.publish("ev", "safe")
    assert count == 1
    assert good_results == ["safe"]


def test_event_bus_concurrency():
    bus = EventBus()
    counter = {"count": 0}
    lock = threading.Lock()

    def handler(val):
        with lock:
            counter["count"] += val

    bus.subscribe("inc", handler)

    threads = []
    for _ in range(10):
        t = threading.Thread(target=lambda: bus.publish("inc", 1))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert counter["count"] == 10


def test_global_bus_helpers():
    received = []
    subscribe("global_topic", lambda x: received.append(x))
    publish("global_topic", 42)
    assert received == [42]

