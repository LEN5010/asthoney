import asyncio

from src.realtime.event_bus import EventBus


def test_publish_lands_in_replay_and_subscriber_queue():
    async def scenario() -> None:
        bus = EventBus(replay_size=8)
        queue = await bus.subscribe()
        event = await bus.publish("intent.detected", {"category": "discovery"})
        assert event["type"] == "intent.detected"
        assert event["seq"] == 1
        replayed = bus.replay_buffer(limit=4)
        assert replayed[-1]["event_id"] == event["event_id"]
        queued = queue.get_nowait()
        assert queued["data"]["category"] == "discovery"
        await bus.unsubscribe(queue)
        assert bus.subscriber_count == 0

    asyncio.run(scenario())


def test_slow_subscriber_drops_oldest_instead_of_blocking():
    async def scenario() -> None:
        bus = EventBus(replay_size=4)
        queue = await bus.subscribe()
        # 队列容量 256，先填满再确认最新事件仍能进入。
        for index in range(260):
            await bus.publish("session.activity", {"n": index})
        remaining = []
        while True:
            try:
                remaining.append(queue.get_nowait()["data"]["n"])
            except asyncio.QueueEmpty:
                break
        assert 259 in remaining
        assert 0 not in remaining
        await bus.unsubscribe(queue)

    asyncio.run(scenario())


def test_publish_nowait_holds_task_reference_until_done():
    async def scenario() -> None:
        bus = EventBus()
        bus.publish_nowait("alert.raised", {"severity": "high"})
        assert len(bus._background_tasks) == 1
        await asyncio.sleep(0.05)
        assert len(bus._background_tasks) == 0
        assert bus.replay_buffer()[-1]["type"] == "alert.raised"

    asyncio.run(scenario())
