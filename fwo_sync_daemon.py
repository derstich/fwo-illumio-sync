#!/usr/bin/env python3
"""
Listens for PostgreSQL NOTIFY on fwo_modelling_changed and triggers
an immediate --export-only sync. Debounces rapid changes (1s window).
"""
import select, subprocess, time, logging
import psycopg2

SYNC_SCRIPT = "/usr/local/fworch/bin/fwo_pce_sync.py"
DEBOUNCE_S  = 2   # wait this long after last change before syncing

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-5s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger()

def run_sync():
    log.info("Change detected — running export sync...")
    r = subprocess.run(["python3", SYNC_SCRIPT, "--export-only"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if any(k in line for k in ["Created", "Updated", "Deleted", "Done", "ERROR"]):
            log.info("  " + line.strip())
    if r.returncode != 0:
        log.error("Sync failed:\n" + r.stderr[-500:])

def main():
    log.info("FWO sync daemon starting...")
    conn = psycopg2.connect("dbname=fworchdb user=postgres")
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("LISTEN fwo_modelling_changed;")
    log.info("Listening for modelling changes on fwo_modelling_changed...")

    pending = False
    last_notify = 0

    while True:
        ready = select.select([conn], [], [], 1.0)[0]
        if ready:
            conn.poll()
            if conn.notifies:
                conn.notifies.clear()
                pending = True
                last_notify = time.time()

        if pending and (time.time() - last_notify) >= DEBOUNCE_S:
            pending = False
            run_sync()

if __name__ == "__main__":
    main()
