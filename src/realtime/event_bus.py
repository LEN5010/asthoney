"""进程内事件总线：把控制面产生的事件实时广播给 WebSocket 订阅者。

设计约束：
- 广播绝不能阻塞诱捕主链路。订阅者队列满时丢弃最旧事件而不是等待。
- 保留最近 N 条事件作为回放缓冲，新连接进来可立刻看到上下文，而不是空白面板。
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

# 单个订阅者的积压上限；超过说明该客户端消费不过来，丢弃最旧事件保活。
SUBSCRIBER_QUEUE_SIZE = 256
# 服务端保留的回放缓冲长度。
REPLAY_BUFFER_SIZE = 120


class EventBus:
    """轻量 pub/sub。无外部依赖，单进程内使用。"""

    def __init__(self, *, replay_size: int = REPLAY_BUFFER_SIZE) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._replay: deque[dict[str, Any]] = deque(maxlen=replay_size)
        self._lock = asyncio.Lock()
        self._sequence = 0

    async def publish(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        """广播一条事件，返回落盘/回放用的完整事件体。"""
        self._sequence += 1
        event = {
            "event_id": str(uuid4()),
            "seq": self._sequence,
            "type": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        self._replay.append(event)

        # 复制一份订阅者集合再投递，避免投递过程中集合被并发修改。
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # 慢消费者：丢掉它最旧的一条，再塞入最新的一条。
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    logger.debug("Dropping event for a saturated subscriber")
        return event

    def publish_nowait(self, event_type: str, data: dict[str, Any]) -> None:
        """同步上下文中的即发即忘广播（如异常处理分支）。"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.publish(event_type, data))

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    def replay_buffer(self, limit: int = 40) -> list[dict[str, Any]]:
        """返回最近事件，供新订阅者补齐上下文。"""
        if limit <= 0:
            return []
        return list(self._replay)[-limit:]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def clear_replay(self) -> None:
        self._replay.clear()
