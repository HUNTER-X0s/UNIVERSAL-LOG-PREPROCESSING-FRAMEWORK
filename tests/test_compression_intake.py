import gzip
import zstandard as zstd
from ulpf_api.app import create_app
from starlette.testclient import TestClient


def test_compression_intake():
    app = create_app()
    client = TestClient(app)

    raw_bytes = b'{"event": "test_decompression", "level": "INFO"}'

    # 1. Test GZIP
    gz_bytes = gzip.compress(raw_bytes)
    res_gz = client.post("/api/v1/intake/raw", content=gz_bytes, headers={"Content-Encoding": "gzip"})
    assert res_gz.status_code == 202
    assert res_gz.json().get("accepted") is True

    # 2. Test ZSTD
    cctx = zstd.ZstdCompressor()
    zstd_bytes = cctx.compress(raw_bytes)
    res_zstd = client.post("/api/v1/intake/raw", content=zstd_bytes, headers={"Content-Encoding": "zstd"})
    assert res_zstd.status_code == 202
    assert res_zstd.json().get("accepted") is True

    # 3. Test NONE (uncompressed)
    res_raw = client.post("/api/v1/intake/raw", content=raw_bytes)
    assert res_raw.status_code == 202
    assert res_raw.json().get("accepted") is True

    # 4. Test Alias Route (/api/v1/ingest/raw)
    res_alias = client.post("/api/v1/ingest/raw", content=gz_bytes, headers={"Content-Encoding": "gzip"})
    assert res_alias.status_code == 202
    assert res_alias.json().get("accepted") is True
