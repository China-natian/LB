Build from the repository root so the image can compile the vendored onego source:

```
docker build -f container/Dockerfile -t lb-worker-container .
```

The image builds `third_party/onego/build-src` in a Go stage and installs it as
`/usr/local/bin/onego`; no Go toolchain is required on the host.
