# Examples

| File | Use |
|---|---|
| `payloads.txt` | one payload per line, for `python scripts/e2e_pipeline.py --payloads examples/payloads.txt` |
| `payload.txt` | a multi-line text payload, for `python qr-create.py --payload examples/payload.txt --file ...` |
| `plain_qr/` | **unsigned** baseline: a plain QR generator (`generator.py`) and an OpenCV scanner (`scanner.py`) without any cryptography, kept from the v1 repository to show what an ordinary QR code contains |

The plain tools are independent of `secureqr` and write to `qr_img/`:

```bash
python examples/plain_qr/generator.py --text "Hello"
```
```bash
python examples/plain_qr/scanner.py --image qr_img/<file>.png
```
