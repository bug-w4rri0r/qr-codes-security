# Benchmark scripts used for the paper (v1, archived unchanged)

These are the scripts that produced the performance numbers reported in the paper
(Table "System performance benchmark"). They are kept byte-for-byte as they were run, for
transparency. They target the **v1** tools; use the maintained v2 benchmarks in `../` to
measure the current code.

| Script | What it measures | Notes |
|---|---|---|
| `ed25519_raw_benchmark.py` (was `qr-test.py`) | raw Ed25519 signing and verification | `iterations = 10000`, ~70-byte message, `time.time()` |
| `benchmark_full_pipeline.py` | full in-process pipeline: sign + CBOR + ZLIB + Base64 + QR (segno, ECC H, scale 3) + PNG, then OpenCV read + decode + verify | `ITERATIONS = 1000`, Root-Only mode |
| `benchmark_cli_pipeline.py` | same through the CLI scripts (`qr-create.py`, `qr-read.py`), includes interpreter start-up | `ITERATIONS = 100` |
| `pprod_test_2tier_pipeline.py`, `test_2tier_pipeline.py` | end-to-end functional test of the Root+App chain with realistic ~150-byte URLs | not a timing benchmark |

Differences worth knowing when comparing with the v2 benchmarks:
- the raw Ed25519 numbers came from 10,000 iterations (the paper table states 1,000 iterations for the whole benchmark);
- `time.time()` was used; v2 uses `time.perf_counter()`;
- the full-pipeline run used ECC level H and Root-Only mode.
