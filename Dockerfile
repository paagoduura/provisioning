FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/ota-api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ota-api /ota-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ota-api"]
