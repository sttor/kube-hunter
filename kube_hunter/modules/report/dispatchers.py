import logging
import os
import requests
import uuid

logger = logging.getLogger(__name__)


class HTTPDispatcher:
    def status(self, status="COMPLETED"):
        data = {"status": status}
        try:
            r = requests.post(self.status_url, json=data, headers=self.headers, verify=False)
            print(r.json())
        except Exception as e:
            print(str(e))

    def dispatch(self, report):
        logger.debug("Dispatching report via HTTP")
        dispatch_method = os.environ.get("HTTP_DISPATCH_METHOD", "POST").upper()
        self.dispatch_url = f"{os.environ.get('BASE_URL')}/kubernetes/agent/report/"
        self.status_url = f"{os.environ.get('BASE_URL')}/kubernetes/agent/status/"
        scan_id = os.environ.get("SCAN_ID")
        self.headers = {"Content-Type": "application/json", "Authorization": os.environ.get("HTTP_AUTH_TOKEN",""),
                   "X-SCAN-ID": scan_id, "X-CHUNK-ID": uuid.uuid4().hex }
        self.status("PENDING")
        data = {"PENTEST": report}
        try:
            r = requests.request(
                dispatch_method, self.dispatch_url, json=data, headers=self.headers, verify=False
            )
            r.raise_for_status()
            logger.info(f"Report was dispatched to: {self.dispatch_url}")
            logger.debug(f"Dispatch responded {r.status_code} with: {r.text}")

        except requests.HTTPError:
            logger.exception(f"Failed making HTTP {dispatch_method} to {self.dispatch_url}, " f"status code {r.status_code}")
        except Exception:
            logger.exception(f"Could not dispatch report to {self.dispatch_url}")
        finally:
            self.status("COMPLETED")



class STDOUTDispatcher:
    def dispatch(self, report):
        logger.debug("Dispatching report via stdout")
        print(report)
