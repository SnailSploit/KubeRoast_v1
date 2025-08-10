from typing import Iterator, Tuple

def iter_containers(pod) -> Iterator[Tuple[object, str]]:
    # main containers
    for c in (pod.spec.containers or []):
        yield c, c.name
    # init containers
    for c in (pod.spec.init_containers or []):
        yield c, f"{c.name} (init)"
    # ephemeral containers
    for c in (getattr(pod.spec, "ephemeral_containers", []) or []):
        yield c, f"{c.name} (ephemeral)"
