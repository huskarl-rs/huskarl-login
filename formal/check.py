#!/usr/bin/env python3
"""Run finite TLC safety checks, including named expected counterexamples."""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--docker", action="store_true", help="Use pinned Java container instead of local Java")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected_sha256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
    if hashlib.sha256(args.jar.read_bytes()).hexdigest() != expected_sha256:
        parser.error("--jar must be the pinned tla2tools.jar v1.7.4 (see README.md)")
    root = Path(__file__).resolve().parent
    args.output.mkdir(parents=True, exist_ok=True)
    failed = False
    configs = sorted((root / "configs").glob("*.cfg"))
    if not configs:
        parser.error("no TLC configurations found")
    for config in configs:
        expectation = config.read_text().splitlines()[0].removeprefix("\\* EXPECT: ")
        with tempfile.TemporaryDirectory(prefix="huskarl-tlc-") as work:
            if args.docker:
                command = [
                    "docker", "run", "--rm", "--network=none",
                    "-v", f"{root}:/model:ro",
                    "-v", f"{args.jar.resolve()}:/tools/tla2tools.jar:ro",
                    "-w", "/tmp",
                    "eclipse-temurin:21-jre@sha256:d7051a45dd955e4d5d1db4d3f4269fe13d1c6dff8cc6b7ef89fc8577b96c1982",
                    "java", "-XX:+UseParallelGC", "-cp", "/tools/tla2tools.jar",
                    "tlc2.TLC", "-workers", "1", "-seed", "1",
                    "-metadir", "/tmp/states", "-config", f"/model/configs/{config.name}",
                    "/model/SessionLifecycle.tla",
                ]
            else:
                command = [args.java, "-XX:+UseParallelGC", "-cp", str(args.jar.resolve()),
                           "tlc2.TLC", "-workers", "1", "-seed", "1",
                           "-metadir", work, "-config", str(config),
                           str(root / "SessionLifecycle.tla")]
            result = subprocess.run(
                command,
                cwd=work, env={**os.environ, "TLA_LIBRARY": str(root)},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=300, check=False,
            )
        (args.output / f"{config.stem}.log").write_text(result.stdout)
        if expectation == "PASS":
            ok = result.returncode == 0 and "Model checking completed. No error has been found." in result.stdout
        else:
            ok = result.returncode != 0 and f"Invariant {expectation} is violated." in result.stdout
        print(f"{'OK' if ok else 'FAIL'} {config.stem}: {expectation}", flush=True)
        if not ok:
            print(result.stdout)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
