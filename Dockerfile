# Multi-stage build for a distroless, non-root image that carries only the
# nhi-reach binary. The build context is kept minimal on purpose: only the
# module files and the public source directories the binary needs are copied,
# so no private documentation can reach the builder layer even if .dockerignore
# is bypassed.
FROM golang:1.25.13-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG CATALOG_HASH=unknown

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/d4rpell/nhi-reach/internal/version.Version=${VERSION} \
        -X github.com/d4rpell/nhi-reach/internal/version.Commit=${COMMIT} \
        -X github.com/d4rpell/nhi-reach/internal/version.Date=${DATE} \
        -X github.com/d4rpell/nhi-reach/internal/version.CatalogHash=${CATALOG_HASH}" \
      -o /out/nhi-reach ./cmd/nhi-reach

# distroless/static already ships the Debian CA bundle (ca-certificates) and the
# tzdata the tool needs; nothing else is copied into the runtime layer.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/nhi-reach /nhi-reach

USER nonroot:nonroot
ENTRYPOINT ["/nhi-reach"]
