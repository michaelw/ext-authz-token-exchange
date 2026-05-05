package main

import (
	"context"
	"fmt"
	"os"

	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
	"github.com/spf13/cobra"
)

func main() {
	if err := newCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	opts := demo.LoadOptionsFromEnv()
	cmd := &cobra.Command{
		Use:   "demo-scenario [list|all|scenario]",
		Short: "Run read-only token exchange demo scenarios",
		Long:  "Run read-only token exchange demo scenarios against the local-test Gateway API host.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "help" {
				return cmd.Help()
			}
			return run(cmd.Context(), args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "scenario YAML file")
	cmd.Flags().StringVar(&opts.BaseURL, "base-url", opts.BaseURL, "demo gateway base URL")
	cmd.Flags().StringVar(&opts.NamespacePrefix, "namespace-prefix", opts.NamespacePrefix, "team namespace prefix")
	cmd.Flags().StringVar(&opts.SystemNamespace, "system-namespace", opts.SystemNamespace, "central demo namespace")
	cmd.Flags().BoolVar(&opts.InsecureTLS, "insecure-skip-verify", opts.InsecureTLS, "skip TLS verification for demo HTTPS requests")
	return cmd
}

func run(ctx context.Context, command string, opts demo.Options) error {
	cfg, err := demo.LoadConfig(opts)
	if err != nil {
		return err
	}
	switch command {
	case "list":
		for _, sc := range cfg.Scenarios {
			fmt.Println(sc.Name)
		}
		return nil
	case "all":
		var failed int
		for _, sc := range cfg.Scenarios {
			if _, err := runOne(ctx, opts, sc); err != nil {
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("Completed with %d failed scenario(s).", failed)
		}
		fmt.Println()
		fmt.Println("All scenarios passed.")
		return nil
	default:
		sc, ok := cfg.Find(command)
		if !ok {
			return fmt.Errorf("error: unknown scenario %q", command)
		}
		_, err := runOne(ctx, opts, sc)
		return err
	}
}

func runOne(ctx context.Context, opts demo.Options, sc demo.Scenario) (demo.Result, error) {
	result, err := demo.Run(ctx, opts, sc)
	printScenario(result)
	if err != nil {
		fmt.Println("Result:    FAIL")
		return result, err
	}
	fmt.Println("Result:    PASS")
	return result, nil
}

func printScenario(result demo.Result) {
	sc := result.Scenario
	obs := result.Observed
	fmt.Println()
	fmt.Printf("Scenario:  %s\n", sc.Name)
	fmt.Printf("Summary:   %s\n", sc.Description)
	fmt.Printf("Request:   %s %s\n", sc.Request.Method, sc.Request.Path)
	if sc.Request.Bearer != "" {
		fmt.Printf("Input:     Authorization: Bearer %s\n", sc.Request.Bearer)
	} else {
		fmt.Println("Input:     Authorization: <none>")
	}
	fmt.Printf("Policy:    %s\n", sc.Policy)
	fmt.Printf("Exchange:  %s\n", sc.Exchange)
	if sc.Behavior.Summary != "" {
		fmt.Printf("Issuer:    %s\n", sc.Behavior.Summary)
	}
	fmt.Printf("Expected:  HTTP %d\n", sc.Expect.Status)
	if sc.Expect.Auth != "" {
		fmt.Printf("Expected:  upstream Authorization: %s\n", sc.Expect.Auth)
	}
	if sc.Expect.Error != "" {
		fmt.Printf("Expected:  error=%s\n", sc.Expect.Error)
	}
	fmt.Printf("Observed:  HTTP %d\n", obs.Status)
	if obs.Auth != "" {
		fmt.Printf("Observed:  upstream Authorization: %s\n", obs.Auth)
	}
	if obs.ErrorCode != "" {
		fmt.Printf("Observed:  error=%s\n", obs.ErrorCode)
	}
	if obs.WWW != "" {
		fmt.Printf("Observed:  WWW-Authenticate: %s\n", obs.WWW)
	}
	if obs.CORSOrigin != "" {
		fmt.Printf("Observed:  Access-Control-Allow-Origin: %s\n", obs.CORSOrigin)
	}
	if obs.ContentType != "" {
		fmt.Printf("Observed:  Content-Type: %s\n", obs.ContentType)
	}
	if obs.Elapsed != "" {
		fmt.Printf("Observed:  elapsed=%s\n", obs.Elapsed)
	}
	for _, failure := range result.Failures {
		fmt.Fprintf(os.Stderr, "FAIL: %s: expected %q, got %q\n", failure.Label, failure.Want, failure.Got)
	}
}
