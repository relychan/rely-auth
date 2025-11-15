// Package main start an http server for auth hooks.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hasura/gotel"
	"github.com/relychan/gohttps"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/handler"
)

var BuildVersion string

func main() {
	err := runServer()
	if err != nil {
		log.Fatal(err)
	}
}

func runServer() error {
	envVars, err := GetEnvironment()
	if err != nil {
		return err
	}

	logger, _, err := gotel.NewJSONLogger(envVars.Server.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Handle SIGINT (CTRL+C) gracefully.
	ctx, stop := signal.NotifyContext(context.TODO(), os.Interrupt)

	ts, err := gotel.SetupOTelExporters(ctx, &envVars.Telemetry, BuildVersion, logger)
	if err != nil {
		stop()

		return err
	}

	defer func() {
		stop()
		goutils.CatchWarnContextErrorFunc(ts.Shutdown)
	}()

	authManager, err := InitAuthManager(&envVars, ts.Logger)
	if err != nil {
		return err
	}

	router := setupRouter(&envVars, authManager, ts.Logger)

	err = gohttps.ListenAndServe(ctx, router, envVars.Server)
	if err != nil {
		return fmt.Errorf("failed to serve http server: %w", err)
	}

	return nil
}

func setupRouter(
	envVars *Environment,
	authManager *auth.RelyAuthManager,
	logger *slog.Logger,
) *chi.Mux {
	router := gohttps.NewRouter(envVars.Server, logger)
	router.Use(middleware.AllowContentType("application/json"))

	pathAuthDDN := "/auth/ddn"
	pathAuthHGE := "/auth/hasura"
	ddnHandlers := handler.NewHasuraDDNAuthHookHandler(authManager)
	hgeHandlers := handler.NewHasuraGraphQLEngineAuthHookHandler(authManager)

	router.Get(pathAuthDDN, ddnHandlers.Get)
	router.Post(pathAuthDDN, ddnHandlers.Post)
	router.Get(pathAuthHGE, hgeHandlers.Get)
	router.Post(pathAuthHGE, hgeHandlers.Post)

	return router
}
