package main

import (
	"fmt"
	"log"

	"hw05chat/internal/app"
	"hw05chat/internal/config"
	"hw05chat/internal/server"
)

func main() {
	cfg := config.Parse()
	srv := server.New(cfg, app.NewHub())

	fmt.Printf("Chat server: http://%s\n", cfg.Address())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
