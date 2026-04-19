package commands

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"hw03dns/internal/sysinfo"
)

type Env struct {
	Summary        sysinfo.NetworkSummary
	SnapLen        int32
	ReadTimeoutMS  int32
	ARPRetryCount  int
	ARPWait        time.Duration
	DNSWait        time.Duration
	ConfigPath     string
	DefaultRootDNS net.IP
}

type Runner interface {
	Name() string
	Description() string
	Usage() string
	Run(ctx context.Context, args []string) error
}

func parsePositiveSeconds(raw string) (time.Duration, error) {
	sec, err := strconv.Atoi(raw)
	if err != nil || sec <= 0 {
		return 0, fmt.Errorf("ожидается положительное число секунд, получено: %q", raw)
	}
	return time.Duration(sec) * time.Second, nil
}
