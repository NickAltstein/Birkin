"""
Signing-key creation race.

Parallel hooks on a fresh install each try to create the Ed25519 key. If more
than one key ends up in use, receipts in the same ledger are signed with
different keys and `receiptd verify` fails on an untouched ledger.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


WORKER = """
import sys
import time
from pathlib import Path

from receiptd.crypto import get_signing_key

barrier, key_dir = map(Path, sys.argv[1:])
while not barrier.exists():
    time.sleep(0.002)
sys.stdout.buffer.write(get_signing_key(key_dir=key_dir).public_pem_bytes)
"""


@pytest.mark.parametrize("attempt", range(3))
def test_simultaneous_key_creation_yields_one_key(tmp_path, attempt):
    barrier = tmp_path / "start"
    key_dir = tmp_path / "keys"
    processes = []
    try:
        for _ in range(16):
            processes.append(subprocess.Popen(
                [sys.executable, "-c", WORKER, str(barrier), str(key_dir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ))
        barrier.touch()
        public_keys = []
        for proc in processes:
            output, errors = proc.communicate(timeout=20)
            assert proc.returncode == 0, errors.decode()
            public_keys.append(output)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    assert len(set(public_keys)) == 1
    assert (tmp_path / "keys" / "receiptd_ed25519.pub.pem").read_bytes() == public_keys[0]
    assert not [p.name for p in (tmp_path / "keys").iterdir() if ".tmp." in p.name]


def test_key_creation_without_hard_links(tmp_path, monkeypatch):
    from receiptd import crypto

    def no_link(src, dst):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(crypto.os, "link", no_link)
    key_dir = tmp_path / "keys"
    first = crypto.get_signing_key(key_dir=key_dir)
    second = crypto.get_signing_key(key_dir=key_dir)
    assert first.public_pem_bytes == second.public_pem_bytes
    assert (key_dir / "receiptd_ed25519.pub.pem").read_bytes() == first.public_pem_bytes


def test_card_and_hook_recover_missing_public_key(tmp_path, monkeypatch):
    from receiptd.card.signing import get_key_pair
    from receiptd.crypto import get_signing_key

    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    original = get_signing_key(key_dir=key_dir)
    public_path = key_dir / "receiptd_ed25519.pub.pem"
    public_path.unlink()

    _, card_public = get_key_pair()

    assert card_public == original.public_pem_bytes
    assert public_path.read_bytes() == original.public_pem_bytes
