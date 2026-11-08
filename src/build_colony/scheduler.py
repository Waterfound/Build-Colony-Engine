from __future__ import annotations

from dataclasses import dataclass

from .errors import SchedulingError
from .models import Domain, Profile


@dataclass(frozen=True)
class Schedule:
    waves: tuple[tuple[str, ...], ...]

    def wave_for(self, domain_id: str) -> int:
        for index, wave in enumerate(self.waves, start=1):
            if domain_id in wave:
                return index
        raise KeyError(domain_id)


def _conflicts(left: Domain, right: Domain) -> bool:
    if set(left.write_scopes) & set(right.write_scopes):
        return True
    if set(left.exclusive_resources) & set(right.exclusive_resources):
        return True
    return False


def build_schedule(profile: Profile) -> Schedule:
    by_id = {domain.id: domain for domain in profile.domains}
    remaining = set(by_id)
    completed: set[str] = set()
    waves: list[tuple[str, ...]] = []

    while remaining:
        ready = sorted(
            domain_id
            for domain_id in remaining
            if set(by_id[domain_id].dependencies) <= completed
        )
        if not ready:
            raise SchedulingError("dependency graph cannot make progress")

        wave: list[str] = []
        for domain_id in ready:
            candidate = by_id[domain_id]
            if any(_conflicts(candidate, by_id[selected]) for selected in wave):
                continue
            wave.append(domain_id)

        if not wave:
            raise SchedulingError("ready work exists but all work was unschedulable")

        waves.append(tuple(wave))
        completed.update(wave)
        remaining.difference_update(wave)

        # Ready work that conflicted with this wave deliberately remains in
        # `remaining`; it is serialized after the shared state is released.

    return Schedule(waves=tuple(waves))
