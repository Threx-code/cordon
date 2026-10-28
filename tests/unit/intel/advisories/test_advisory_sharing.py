"""One bundled advisory database per process, safe to share between threads (PERF-1).

```
  bundled() ──► the same instance every time ──► reset_caches() ──► a fresh one
  threads asking at once ──► one merge, every thread sees all of it
```
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase
from cordon_scanner.intel.advisories.shipped import ShippedAdvisories


class TestAdvisorySharing:
    def test_bundled_is_one_instance_until_a_feed_update(self) -> None:
        first = AdvisoryDatabase.bundled()
        assert AdvisoryDatabase.bundled() is first
        ShippedAdvisories.reset_caches()
        assert AdvisoryDatabase.bundled() is not first

    def test_threads_asking_at_once_all_see_the_whole_answer(self) -> None:
        ShippedAdvisories.reset_caches()
        expected = len(AdvisoryDatabase.bundled().matching("npm", "event-stream", "3.3.6"))
        ShippedAdvisories.reset_caches()
        database = AdvisoryDatabase.bundled()
        with ThreadPoolExecutor(8) as pool:
            counts = list(
                pool.map(
                    lambda _: len(database.matching("npm", "event-stream", "3.3.6")), range(32)
                )
            )
        assert expected >= 1
        assert counts == [expected] * 32
