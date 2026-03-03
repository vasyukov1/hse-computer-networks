package commands

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// Env содержит общие настройки команд
type Env struct {
	InterfaceName  string
	SnapLen        int32
	ReadTimeoutMS  int32
	DiscoveryWait  time.Duration
	DiscoveryTries int
}

// Runner - интерфейс команд REPL
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
