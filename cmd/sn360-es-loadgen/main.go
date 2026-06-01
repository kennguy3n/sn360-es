// Command sn360-es-loadgen is the local-dev companion binary that
// the WS-6a k6 harness drives during 5,000-tenant load scenarios.
//
// k6 cannot speak the NATS JetStream wire protocol directly, and
// hitting the production /v1/push/{provider}/{tenant} endpoint
// requires real Google Pub/Sub / Microsoft Graph signature payloads
// that are awkward to synthesise at load. Rather than relax the
// production push signature verifier or stub anything internal
// (forbidden by the WS-6a brief), this binary fronts the **real**
// pipeline with a thin HTTP -> NATS shim:
//
//	POST /publish          -> publishes a dto.EvaluateRequest on
//	                          subject `es.evaluate.request`. Everything
//	                          downstream (consumers, Tier 0/1/2,
//	                          banner action) runs unchanged.
//	POST /publish/batch    -> same payload, but takes an array; lets
//	                          the k6 scenarios batch up to ~100
//	                          messages per HTTP call to avoid network
//	                          dominating the run.
//	GET  /healthz          -> 200 when the NATS connection is alive.
//	GET  /stats            -> JSON publish counter (best-effort).
//
// And a `bootstrap` subcommand that pre-provisions tenants via
// direct Postgres INSERT so the scenarios can address 5,000
// distinct tenant_id values without going through the (much
// heavier) onboarding OAuth flow:
//
//	sn360-es-loadgen bootstrap \
//	    -postgres-url=postgres://sn360es:sn360es@localhost:5432/sn360es?sslmode=disable \
//	    -count=5000 \
//	    -tenant-prefix=00000000-0000-0000-0000- \
//	    -out=tests/load/results/tenants.json
//
// Both subcommands deliberately bind to 127.0.0.1 by default — the
// binary is a local-dev / CI tool, not a production service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const (
	cmdBootstrap = "bootstrap"
	cmdPublisher = "publisher"
)

func usage() {
	fmt.Fprintf(os.Stderr, `sn360-es-loadgen is the WS-6a local-dev load companion.

Usage:
  sn360-es-loadgen <subcommand> [flags]

Subcommands:
  %s    Provision N tenants in Postgres so k6 can address them.
  %s    Run an HTTP -> NATS publish shim k6 drives during a scenario.

Each subcommand has its own -h flag. The default bind for the
publisher is 127.0.0.1:9099 (loopback only).
`, cmdBootstrap, cmdPublisher)
}

func main() {
	// run() owns all the resources that need defers (signal
	// context, etc.); main() is left as a tiny wrapper so any
	// non-zero exit can call os.Exit without leaking defers
	// inside the workhorse function.
	os.Exit(run(os.Args[1:]))
}

func run(rawArgs []string) int {
	if len(rawArgs) < 1 {
		usage()
		return 2
	}
	sub := rawArgs[0]
	args := rawArgs[1:]

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch sub {
	case "-h", "--help":
		usage()
		return 0
	case cmdBootstrap:
		err = runBootstrap(ctx, logger, args)
	case cmdPublisher:
		err = runPublisher(ctx, logger, args)
	default:
		fmt.Fprintf(os.Stderr, "sn360-es-loadgen: unknown subcommand %q\n\n", sub)
		usage()
		return 2
	}
	if err != nil {
		// Treat context cancellation as graceful shutdown rather
		// than a hard error so the CI workflow's `kill -TERM`
		// teardown does not flip the job to red on a clean
		// SIGTERM.
		if errors.Is(err, context.Canceled) {
			logger.Info("sn360-es-loadgen: shutdown")
			return 0
		}
		logger.Error("sn360-es-loadgen: "+sub+" failed", slog.Any("error", err))
		return 1
	}
	return 0
}

// newFlagSet returns a flag set that exits with the standard help
// behaviour but writes to stderr instead of stdout so error / help
// output never gets piped into a result artefact by mistake.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
