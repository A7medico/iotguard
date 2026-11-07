"""
scripts/9_utilities/event_bus.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Thread-Safe In-Memory Pub/Sub Event Bus (Layer 0)

Provides a lightweight, thread-safe publish-subscribe event bus to decouple
higher and lower architectural layers (e.g. Layer 3 ML/Inference publishing
alerts without importing Layer 4 Dashboard).
-----------------------------------------------------------------------------
"""

import threading
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("event_bus")


class EventBus:
    """Thread-safe in-memory pub/sub event bus."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[..., Any]]] = {}
        self._lock = threading.RLock()

    def subscribe(self, topic: str, callback: Callable[..., Any]) -> None:
        """Register a callback for a specific event topic."""
        if not callable(callback):
            raise TypeError("Subscriber callback must be callable")
        with self._lock:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            if callback not in self._subscribers[topic]:
                self._subscribers[topic].append(callback)

    def unsubscribe(self, topic: str, callback: Callable[..., Any]) -> bool:
        """Unregister a callback from an event topic. Returns True if removed."""
        with self._lock:
            if topic in self._subscribers and callback in self._subscribers[topic]:
                self._subscribers[topic].remove(callback)
                if not self._subscribers[topic]:
                    del self._subscribers[topic]
                return True
            return False

    def publish(self, topic: str, *args: Any, **kwargs: Any) -> int:
        """
        Publish an event to all subscribers of a topic.
        Returns the count of subscribers successfully invoked.
        """
        with self._lock:
            callbacks = list(self._subscribers.get(topic, []))

        invoked = 0
        for cb in callbacks:
            try:
                cb(*args, **kwargs)
                invoked += 1
            except Exception as e:
                logger.error(f"Error in subscriber {cb} for topic '{topic}': {e}", exc_info=True)
        return invoked

    def clear(self, topic: Optional[str] = None) -> None:
        """Clear subscribers for a given topic or all topics."""
        with self._lock:
            if topic is not None:
                self._subscribers.pop(topic, None)
            else:
                self._subscribers.clear()

    def get_subscribers(self, topic: str) -> List[Callable[..., Any]]:
        """Return a copy of subscribers registered for a topic."""
        with self._lock:
            return list(self._subscribers.get(topic, []))


# Global singleton instance
_GLOBAL_BUS = EventBus()


def get_event_bus() -> EventBus:
    """Return the global event bus instance."""
    return _GLOBAL_BUS


def subscribe(topic: str, callback: Callable[..., Any]) -> None:
    """Subscribe a callback to a topic on the global bus."""
    _GLOBAL_BUS.subscribe(topic, callback)


def unsubscribe(topic: str, callback: Callable[..., Any]) -> bool:
    """Unsubscribe a callback from a topic on the global bus."""
    return _GLOBAL_BUS.unsubscribe(topic, callback)


def publish(topic: str, *args: Any, **kwargs: Any) -> int:
    """Publish an event to a topic on the global bus."""
    return _GLOBAL_BUS.publish(topic, *args, **kwargs)


def clear_subscribers(topic: Optional[str] = None) -> None:
    """Clear subscribers on the global bus."""
    _GLOBAL_BUS.clear(topic)

