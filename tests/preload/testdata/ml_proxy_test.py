#!/usr/bin/env python3
"""ML + tunnel network smoke test for uwgsocks wrapper.

Trains a RandomForestClassifier on the iris dataset (CPU-only, no GPU),
then opens a TCP connection through the tunnel echo server to verify
network interception is working. Prints ML_DONE on success.
"""
import sys
import socket


def run_ml():
    from sklearn.datasets import load_iris
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    X, y = load_iris(return_X_y=True)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=1)
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"RF accuracy: {acc:.3f}", flush=True)
    assert acc > 0.85, f"accuracy too low: {acc}"


def run_network(host, port, sentinel):
    """Connect via (intercepted) socket and verify echo."""
    with socket.create_connection((host, int(port)), timeout=10) as s:
        msg = (sentinel + "\n").encode()
        s.sendall(msg)
        buf = b""
        while sentinel.encode() not in buf:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
        assert sentinel.encode() in buf, f"echo missing from {buf!r}"
    print(f"network echo OK: {sentinel}", flush=True)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "100.64.94.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "18080"
    sentinel = sys.argv[3] if len(sys.argv) > 3 else "ml-proxy-test"

    run_ml()
    run_network(host, port, sentinel)
    print("ML_DONE", flush=True)
