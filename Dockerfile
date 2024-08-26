FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
FROM scratch
COPY --from=builder /app/main /main
COPY --from=builder /app/templates /templates
EXPOSE 8000
CMD ["/main"]
