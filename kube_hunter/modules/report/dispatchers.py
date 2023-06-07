import logging
import os
import requests
import uuid

logger = logging.getLogger(__name__)


class HTTPDispatcher:
    def dispatch(self, report):
        logger.debug("Dispatching report via HTTP")
        dispatch_method = os.environ.get("KSEC_HTTP_DISPATCH_METHOD", "POST").upper()
        dispatch_url = os.environ.get("KSEC_HTTP_DISPATCH_URL", "https://localhost/")
        scan_id = os.environ.get("KSEC_PENTEST_SCAN_ID")
        headers = {"Content-Type": "application/json", "Authorization": os.environ.get("HTTP_AUTH_TOKEN", "")}
        data = {"scan_id": scan_id, "output": report, "identifier": uuid.uuid4().hex}
        try:
            r = requests.post(dispatch_url, data=data, headers=headers, verify=False)
            r.raise_for_status()
            logger.info(f"Report was dispatched to: {dispatch_url}")
            logger.debug(f"Dispatch responded {r.status_code} with: {r.text}")

        except requests.HTTPError:
            logger.exception(f"Failed making HTTP {dispatch_method} to {dispatch_url}, " f"status code {r.status_code}")
        except Exception:
            logger.exception(f"Could not dispatch report to {dispatch_url}")


class STDOUTDispatcher:
    def dispatch(self, report):
        logger.debug("Dispatching report via stdout")
        print(report)
