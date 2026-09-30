"""Development only: run with scanoss==1.54.2 installed in an isolated environment."""

import hashlib
import inspect
import json
from pathlib import Path

from scanoss.winnowing import Winnowing


def main():
    directory = Path(__file__).resolve().parent
    root = directory.parents[2]
    reference = (root / "LICENSE-NOTICES/scanoss-winnowing/winnowing.py").read_bytes()
    source_hash = hashlib.sha256(reference).hexdigest()
    assert source_hash == "ec606d89ddd0d2d49c193cf74147e7806ee68a573a9865cf714bf586bea9e0d5"
    assert Path(inspect.getfile(Winnowing)).read_bytes() == reference
    oracle = Winnowing(all_extensions=True)
    sample = b"int Calculate(int Value) { return Value * 17 + 234; }\n"
    cases = [
        ("empty", b""),
        ("short", b"hello\n"),
        ("boundary92", b"a" * 92),
        ("boundary93", b"a" * 93),
        ("repeated", b"a" * 1024),
        ("punctuation", sample * 20),
        ("unicode", ("Stra\u00dfe\u6f22\u5b57\U0001f980 ABC123; \n" * 60).encode()),
        ("invalid_utf8", sample * 10 + b"\xff\xfe\x00" + sample * 10),
        ("crlf", sample.replace(b"\n", b"\r\n") * 20),
        ("cr", sample.replace(b"\n", b"\r") * 20),
        ("mixed", sample * 10 + sample.replace(b"\n", b"\r\n") * 10 + b"\r"),
        ("blank_lines", (b"\n\n" + sample + b"\n") * 20),
        ("hash_format", bytes(range(256)) * 30),
    ]
    fixtures = [
        {"id": name, "bytes_hex": data.hex(), "wfp": oracle.wfp_for_contents(name, False, data)}
        for name, data in cases
    ]
    output = {
        "revision": "0c1292bd4d53bc504804411dd42ff1ab0fa7aa76",
        "source_sha256": source_hash,
        "cases": fixtures,
    }
    (directory / "oracle.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
