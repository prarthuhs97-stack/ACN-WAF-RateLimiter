
import csv
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE_URL = "http://127.0.0.1:8080"
OUTPUT_FILE = Path(__file__).parent / "baseline_results.csv"

# Set this to match the server currently running.
PIPELINE = "rate_limit_first"

NUM_REQUESTS = 100
REQUEST_PATH = "/index.html"

def send_request():
    url = BASE_URL + REQUEST_PATH
    start = time.perf_counter()
    status = None
    error = ""
    response_size = 0

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ACN-Experiment/1.0"}
        )
        with urllib.request.urlopen(request, timeout=10) as response:
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
    file_exists = OUTPUT_FILE.exists()

    with OUTPUT_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists or OUTPUT_FILE.stat().st_size == 0:
            writer.writerow([
                "timestamp", "pipeline", "scenario", "request_number",
                "path", "status_code", "latency_ms", "response_size", "error"
            ])

        for number in range(1, NUM_REQUESTS + 1):
            status, latency, size, error = send_request()

            writer.writerow([
                datetime.now().isoformat(timespec="milliseconds"),
                PIPELINE, "high_rate", number,
                REQUEST_PATH, status, latency, size, error
            ])
            file.flush()

            print(
                f"{number:02}/{NUM_REQUESTS} "
                f"status={status} latency={latency} ms "
                f"bytes={size}"
                + (f" error={error}" if error else "")
            )

            # time.sleep(0.2)

    print(f"\nResults appended to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
