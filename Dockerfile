FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /screener .

FROM scratch
COPY --from=build /screener /screener
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/screener"]
