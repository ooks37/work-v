FROM golang:alpine AS builder

WORKDIR /build

# 安装基础编译环境
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/work-v-master ./cmd/master
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/work-v-agent ./cmd/agent

# 生产精简镜像
FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl bash \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

COPY --from=builder /build/work-v-master /app/work-v-master
COPY --from=builder /build/work-v-agent /app/work-v-agent

# 数据持久化目录 (显式创建, 便于挂载卷时属主/权限正确)
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 8080

ENTRYPOINT ["/app/work-v-master", "-port", "8080", "-db", "/app/data/work-v.db"]
