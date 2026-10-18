
import csv
import random
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE_URL = "http://127.0.0.1:8080"
OUTPUT_FILE = Path(__file__).parent / "mixed_results.csv"

# Match these settings to the server currently running.
PIPELINE = "waf_first"

NUM_LEGITIMATE = 50
NUM_MALICIOUS = 50
RANDOM_SEED = 42

LEGITIMATE_PATHS = [
    "/index.html",
]

MALICIOUS_PATHS = [
    "/?id=%27%20OR%201%3D1%20--",
]

TIMEOUT_SECONDS = 10


def send_request(path):
    url = BASE_URL + path
    start = time.perf_counter()
    status = None
    error = ""
    response_size = 0

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ACN-Mixed-Experiment/1.0"},
        )
        with urllib.request.urlopen(
            request, timeout=TIMEOUT_SECONDS
        ) as response:
            status = response.status
            response_size = len(response.read())

    except urllib.error.HTTPError as exc:
        status = exc.code
        response_size = len(exc.read())

    except Exception as exc:
        error = str(exc)

    latency_ms = (time.perf_counter() - start) * 1000
    return status, round(latency_ms, 3), response_size, error


def main():
    rng = random.Random(RANDOM_SEED)

    requests = (
        [("legitimate", path) for path in LEGITIMATE_PATHS
         for _ in range(NUM_LEGITIMATE // len(LEGITIMATE_PATHS))]
        + [("malicious", path) for path in MALICIOUS_PATHS
           for _ in range(NUM_MALICIOUS // len(MALICIOUS_PATHS))]
    )
    rng.shuffle(requests)

    file_exists = OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0

    with OUTPUT_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp", "pipeline", "scenario", "request_number",
                "request_type", "path", "status_code", "latency_ms",
                "response_size", "error",
            ])

        for number, (request_type, path) in enumerate(requests, start=1):
            status, latency, size, error = send_request(path)

            writer.writerow([
                datetime.now().isoformat(timespec="milliseconds"),
                PIPELINE, "mixed", number, request_type, path,
                status, latency, size, error,
            ])
            file.flush()

            print(
                f"{number:03}/{len(requests)} "
                f"type={request_type} status={status} "
                f"latency={latency} ms bytes={size}"
                + (f" error={error}" if error else "")
            )

    print(f"\nSaved results to: {OUTPUT_FILE}")
    print("This is a local mixed-traffic test, not a GNS3 experiment.")


if __name__ == "__main__":
    main()
