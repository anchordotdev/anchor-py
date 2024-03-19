import os
import pytest


@pytest.fixture(scope="session")
def vcr_config():
    record_mode = os.environ.get("VCR_RECORD_MODE", "none")
    return {
        "filter_headers": ["authorization"],
        "ignore_localhost": True,
        "record_mode": record_mode,
        "decode_compressed_response": True,
    }
