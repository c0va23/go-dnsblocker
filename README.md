# go-dnsblocker

Block dns queries in black list and proxy other queries

*Black list* is plain file with list of blocked domain separated with new line '\n'. File should ended with empty line.

Black list example:
```
google.com
facebook.com

```

## Build

Build require installed and configured golang compiler (tested on 1.5.3).

```bash
git clone https://github.com/c0va23/go-dnsblocker.git
go build dnsblocker.go
echo google.com > hosts
sudo ./dnsblocker
```

## Test dns request

For test you should send dns query to dnsblocker. For example use util **dig**:

```bash
dig @127.0.0.1 google.com
```

## Command line arguments

```
-dns-server string
  	DNS server for proxy not blocked queries (default "192.168.1.1:domain")
-hosts-path string
  	Path to hosts file (default "hosts")
-listen string
  	Listen is pair 'ip:port' (default ":domain")
-log-level string
  	Set minimum log level (default "INFO")
```


