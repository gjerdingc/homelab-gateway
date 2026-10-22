"""Background renewal loop (§8.5)."""

import datetime
import threading

import pki


class Renewer:
    def __init__(self, manager, first_delay=20):
        self.manager = manager
        self.first_delay = first_delay
        self.last_run = None
        self.last_ok = None
        self.last_renewed = []
        self.last_errors = []
        self.next_run = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, name="renewer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def run_once(self):
        try:
            renewed, errors = self.manager.renew_due()
        except Exception as exc:  # the loop must survive anything
            renewed, errors = [], [str(exc)]
            self.manager.actions.write(f"renewal run crashed: {exc}", "ERROR")
        self.last_run = pki.iso(pki.utcnow())
        self.last_renewed, self.last_errors = renewed, errors
        self.last_ok = not errors
        return renewed, errors

    def _loop(self):
        delay = self.first_delay
        while True:
            self.next_run = pki.iso(pki.utcnow() + datetime.timedelta(seconds=delay))
            if self._stop.wait(delay):
                return
            self.run_once()
            delay = self.manager.config.renew_check_hours * 3600
