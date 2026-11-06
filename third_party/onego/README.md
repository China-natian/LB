# onego vendoring

This directory pins the scanner used as LB's default TCP discovery engine.

- `upstream/` - pristine copy of the fork source. Do not edit.
- `build-src/` - the same source plus `patches/0001-scan-summary.patch`.
- `patches/0001-scan-summary.patch` - machine-readable scan summary:
  `--summary <file>` writes `onego.scan-summary.v1` with per-target
  `tested/open/closed/filtered/error/unknown/excluded` and `open_ports`.
- `LICENSE`, `README.upstream.md` - upstream license and documentation.

## Build

Do not build onego on the developer host. `container/Dockerfile` compiles
`build-src/` in a Go stage and installs `/usr/local/bin/onego`; CI builds the
same way from the repository root.

Local worker image build:

```bash
docker build -f container/Dockerfile -t lb-worker-container .
```

## Changing the fork

Edit `build-src/`, then regenerate and verify the patch from this directory:

```bash
/usr/bin/diff -ruN upstream build-src > patches/0001-scan-summary.patch
cp -R upstream /tmp/patch-check && cd /tmp/patch-check \
  && patch -p1 --batch --forward < <repo>/third_party/onego/patches/0001-scan-summary.patch
```

Keep `upstream/` untouched so the patch stays reviewable.
