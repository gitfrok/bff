# syntax=docker/dockerfile:1
# T-0021 / ADR-0035: BFF ships from scratch with no shell or package manager.
FROM docker.io/library/golang:1.27.0-alpine3.23 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/bff ./cmd/bff

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/bff /bff
USER 65532:65532
CMD ["/bff"]
