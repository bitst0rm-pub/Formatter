import threading
import time

from ..core import log


class SyncScrollManager:
    def __init__(self):
        self.running = False
        self.thread = None
        self.lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_sync_scroll()

    def start_sync_scroll(self, target_type, active_view, target_view):
        with self.lock:
            if not self.running:
                self.running = True
                self.thread = threading.Thread(target=self.sync_scroll, args=(target_type, active_view, target_view))
                self.thread.start()

    def stop_sync_scroll(self):
        with self.lock:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=0.4)
            self.thread = None

    def sync_scroll(self, target_type, active_view, target_view):
        try:
            while self.running:
                # log.debug('Sync scroll target: %s', target_type)
                target_view.set_viewport_position(active_view.viewport_position(), False)
                time.sleep(0.25)
        except Exception as e:
            log.error('Error during sync_scroll: %s', e)
        finally:
            self.stop_sync_scroll()


sync_scroll_manager = SyncScrollManager()
