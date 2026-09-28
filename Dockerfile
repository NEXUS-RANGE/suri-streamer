# Этап 1: сборка статического Go-бинарника
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/agent .

# Этап 2: минимальный рантайм-образ
FROM alpine:3.20
COPY --from=build /out/agent /usr/local/bin/agent
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agent"]
