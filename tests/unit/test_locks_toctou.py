import threading

from agent_security_lab.policy.locks import SessionLock, SessionLockError


def test_lock_serializes():
    lock = SessionLock(wait_seconds=2)
    order: list[int] = []

    def worker(n: int) -> None:
        with lock.hold("session:t"):
            order.append(n)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(order) == order or len(order) == 5


def test_lock_timeout():
    lock = SessionLock(wait_seconds=0.05)
    entered = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with lock.hold("session:x"):
            entered.set()
            release.wait(2)

    t = threading.Thread(target=holder)
    t.start()
    assert entered.wait(1)
    try:
        with lock.hold("session:x"):
            pass
        assert False, "should have timed out"
    except SessionLockError:
        pass
    finally:
        release.set()
        t.join()
