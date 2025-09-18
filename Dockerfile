# Shared builder stage with cargo-chef for dependency caching
FROM rust:1.89-alpine AS chef
USER root
# Add cargo-chef to cache dependencies
RUN apk add --no-cache musl-dev && cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
# Capture info needed to build dependencies
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --workspace

# Auth service runtime
FROM alpine:latest AS auth-service
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/auth-service /usr/local/bin/
COPY --from=builder /app/auth-service/assets ./assets
COPY --from=builder /app/auth-service/config ./config
ENV APP__HOME=.
EXPOSE 80
CMD ["auth-service"]

# App service runtime
FROM alpine:latest AS app-service
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/app-service /usr/local/bin/
COPY --from=builder /app/app-service/assets ./assets
COPY --from=builder /app/app-service/templates ./templates
EXPOSE 80
CMD ["app-service"]
