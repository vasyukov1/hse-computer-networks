package config

import (
	"flag"
	"fmt"
)

type Config struct {
	Host string
	Port int
}

func Parse() Config {
	host := flag.String("host", "127.0.0.1", "host for HTTP/WebSocket server")
	port := flag.Int("port", 8080, "port for HTTP/WebSocket server")
	flag.Parse()

	return Config{Host: *host, Port: *port}
}

func (c Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
