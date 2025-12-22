# build context at repo root: docker build -f Dockerfile .
FROM golang:1.25 AS builder

WORKDIR /app

ARG VERSION

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/relychan/rely-auth/server.BuildVersion=${VERSION}" \
    -v -o rely-auth ./server

# stage 2: production image
FROM gcr.io/distroless/static-debian13:nonroot

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/rely-auth /rely-auth

ENTRYPOINT ["/rely-auth"]