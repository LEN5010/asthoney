from src.agents.main_agent import NON_HUMAN_INTERVAL_SECONDS
from main import THEATER_STEP_SECONDS


def test_theater_step_is_slower_than_non_human_interval():
    assert THEATER_STEP_SECONDS == NON_HUMAN_INTERVAL_SECONDS + 0.3
    assert THEATER_STEP_SECONDS > NON_HUMAN_INTERVAL_SECONDS
