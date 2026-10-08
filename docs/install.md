# Installing nhi-reach

`nhi-reach` is distributed in three ways: a precompiled release binary, `go
install`, and a container image. All of them are the same read-only tool.

## Precompiled binary

Download the archive for your OS and architecture from the
[releases page](https://github.com/d4rpell/NHI-reach/releases), unpack it and
verify the checksum:

```sh
# pick the archive for your platform, e.g. linux_amd64
curl -fsSLO https://github.com/d4rpell/NHI-reach/releases/download/v0.1.0/nhi-reach_0.1.0_linux_amd64.tar.gz
curl -fsSLO https://github.com/d4rpell/NHI-reach/releases/download/v0.1.0/nhi-reach_0.1.0_checksums.txt
sha256sum --check --ignore-missing nhi-reach_0.1.0_checksums.txt
tar -xzf nhi-reach_0.1.0_linux_amd64.tar.gz
./nhi-reach version
```

Archives are published for `linux`, `darwin` and `windows` on `amd64` and
`arm64` (`tar.gz`, and `zip` on Windows). Each archive contains the `LICENSE`,
`README.md` and `THIRD_PARTY_NOTICES.md` next to the binary.

## go install

```sh
go install github.com/d4rpell/nhi-reach/cmd/nhi-reach@v0.1.0
```

This requires Go 1.25 or newer. The binary is placed in `$(go env GOPATH)/bin`.
`go install` does **not** run the `-ldflags` injection the release uses, so
`nhi-reach version` prints the default values (`dev`, `none`, `unknown`); the
analysis itself is unaffected. Use a release binary or the container image when
the build metadata matters.

## Container image

The image is `ghcr.io/d4rpell/nhi-reach` on `linux/amd64` and `linux/arm64`. It
runs as a non-root user (`nonroot`, UID 65532) and contains no shell.

```sh
docker run --rm ghcr.io/d4rpell/nhi-reach:0.1.0 version
docker run --rm -v "$PWD/snapshot:/snapshot:ro" ghcr.io/d4rpell/nhi-reach:0.1.0 \
  analyze --from /snapshot -o table
```

For the live mode, mount the kubeconfig read-only. The container can only use a
**self-contained** kubeconfig: one whose cluster uses inline
`certificate-authority-data` (or a CA bundle already trusted inside the image)
and whose user authenticates with an inline token or client certificate. A
kubeconfig that points at files outside the mount, or that uses an `exec`
credential plugin, will not work — the image ships neither those files nor the
plugin executables. Mount the kubeconfig itself (not the whole `$HOME`) and make
it readable by the non-root user, for example:

```sh
docker run --rm -v "$HOME/.kube/config:/kubeconfig:ro" \
  ghcr.io/d4rpell/nhi-reach:0.1.0 analyze --live --kubeconfig /kubeconfig -o table
```

The image is published to GitHub Container Registry. After the first release the
package may need to be made public once, in the repository's *Packages*
settings; until then a pull requires authentication to GHCR.

## Verify the build metadata

A release binary and the container image report their version, commit, build
date and the rules-catalog SHA-256:

```sh
nhi-reach version
# nhi-reach version v0.1.0
# commit:        <sha>
# build date:    <utc>
# rules catalog: <sha256>
```

The catalog hash lets you check that an analysis ran with the catalog you
expect: the same value is written into every report
(`rules_catalog_sha256` in JSON).

## Building from source

See the "Building" section of the top-level [README](../README.md).
