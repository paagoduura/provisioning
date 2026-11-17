FROM golang:1.27.4@sha256:fe517acaa580cc7915457080f850c37e618b3c1e750f98b58fc6429b605147a1 AS build
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/ota-api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG BUILD_VERSION=unknown
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/paagoduura/provisioning" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
COPY --from=build /out/ota-api /ota-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ota-api"]
