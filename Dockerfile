# --- ステージ1: ビルド環境 ---
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 依存関係を先にダウンロード
COPY go.mod go.sum ./
RUN go mod download

# ソースコードをコピー
COPY . .

# アプリケーションをビルド
# CGO_ENABLED=0 は静的バイナリを作成するために重要
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /server main.go

# --- ステージ2: 実行環境 ---
FROM alpine:latest

WORKDIR /root/
COPY --from=builder /server .

# ポート8080を公開
EXPOSE 8080
CMD ["./server"]