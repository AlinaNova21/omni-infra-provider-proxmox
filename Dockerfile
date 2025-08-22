FROM --platform=$BUILDPLATFORM golang:1.24.5-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o omni-infra-provider-proxmox ./cmd/omni-infra-provider-proxmox

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/omni-infra-provider-proxmox /omni-infra-provider-proxmox
ENTRYPOINT ["/omni-infra-provider-proxmox"]