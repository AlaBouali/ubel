import os
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
import requests


def load_environment():
    load_dotenv()

    api_key = os.getenv("UBEL_API_KEY")
    asset_id = os.getenv("UBEL_ASSET_ID")
    endpoint = os.getenv("UBEL_ENDPOINT")

    return api_key, asset_id, endpoint


def create_output_dir(default="./"):
    timestamp = datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    base = Path(default+".ubel/reports/remote") / timestamp
    base.mkdir(parents=True, exist_ok=True)
    return base


def download_file(url: str, destination: Path):
    r = requests.get(url, stream=True, timeout=300)
    r.raise_for_status()

    with open(destination, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)