# A stand-in for Snowflake's SQL API (main.go): komando's own e2e fake,
# built from source here. The name e2e-acct.snowflakecomputing.com resolves
# only on the lab's private network, so komando reaches it through bastion.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /snowflake-fake main.go

FROM alpine:3.22
COPY --from=build /snowflake-fake /usr/local/bin/snowflake-fake
EXPOSE 443
CMD ["/usr/local/bin/snowflake-fake"]
