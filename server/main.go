// Copyright 2026 RelyChan Pte. Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main start an http server for auth hooks.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hasura/gotel"
	"github.com/hasura/gotel/otelutils"
	"github.com/relychan/gohttps"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/config"
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
	envVars, err := config.LoadServerConfig()
	if err != nil {
		return err
	}

	logger, _, err := otelutils.NewJSONLogger(envVars.Server.GetLogLevel())
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

	authManager, err := config.InitAuthManager(ctx, envVars.GetConfigPath(), ts)
	if err != nil {
		goutils.CatchWarnContextErrorFunc(ts.Shutdown)
		stop()

		return err
	}

	defer func() {
		goutils.CatchWarnErrorFunc(authManager.Close)
		goutils.CatchWarnContextErrorFunc(ts.Shutdown)
		stop()
	}()

	router := setupRouter(envVars, authManager, ts)

	err = gohttps.ListenAndServe(ctx, router, &envVars.Server)
	if err != nil {
		return fmt.Errorf("failed to serve http server: %w", err)
	}

	return nil
}

func setupRouter(
	envVars *config.RelyAuthServerConfig,
	authManager *auth.RelyAuthManager,
	exporters *gotel.OTelExporters,
) *chi.Mux {
	router := gohttps.NewRouter(&envVars.Server, exporters.Logger)
	router.Use(
		gotel.NewTracingMiddleware(
			exporters,
			gotel.ResponseWriterWrapperFunc(
				func(w http.ResponseWriter, protoMajor int) gotel.WrapResponseWriter {
					return middleware.NewWrapResponseWriter(w, protoMajor)
				},
			),
		),
		middleware.AllowContentType("application/json"),
	)

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
