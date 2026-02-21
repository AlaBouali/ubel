import requests
import time


class UbelClient:
    def __init__(self, base_url: str, api_key: str, asset_id: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.asset_id = asset_id

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def upload_report(self, report_json: dict):
        payload = {
            "asset_id": self.asset_id,
            "data": report_json
        }

        r = requests.post(
            f"{self.base_url}/scan",
            json=payload,
            headers=self._headers(),
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def poll_until_ready(self, report_id: str, interval=5, timeout=600):
        start = time.time()

        while True:
            if time.time() - start > timeout:
                raise TimeoutError("Report polling timed out")

            r = requests.get(
                f"{self.base_url}/report/{report_id}",
                headers=self._headers(),
                timeout=60,
            )
            r.raise_for_status()
            data = r.json()

            if "json_report" in data:
                return data

            time.sleep(interval)