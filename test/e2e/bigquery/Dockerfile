# A stand-in for BigQuery's REST API and Google's token endpoint (main.go):
# komando's own e2e fake, built from source here. The name
# bigquery.e2e.internal resolves only on the lab's private network, so
# komando reaches it through bastion. (goccy/bigquery-emulator runs, but
# its dry runs fail or run the statement, and it calls every statement a
# SELECT, so it cannot test komando's checks: docs/design/bigquery.md.)
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /bigquery-fake main.go

FROM alpine:3.22
COPY --from=build /bigquery-fake /usr/local/bin/bigquery-fake
EXPOSE 443
CMD ["/usr/local/bin/bigquery-fake"]
