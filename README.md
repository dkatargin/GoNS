# GoNS

DNS server for home usage. Can resolve by global DNS (external dns) and internal
by searching in private_domains list. Also GoNS can work with cache in redis.

**GoNS currently supports only IPv4 addresses for internal resolving**

### Build
```go build -o gons main.go```

### Run
```./gons```