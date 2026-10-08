package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reuse the native test executable as a version-only child, including on
// Windows; no shell, scripts, external compiler, or real FRP is required.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		switch os.Getenv("REMOTETOOL_TEST_FRP_VERSION") {
		case "slow":
			time.Sleep(3500 * time.Millisecond)
			fmt.Println(requiredFRPVersion)
		case "hang":
			time.Sleep(time.Minute)
		case "exit":
			fmt.Fprintln(os.Stderr, "private subprocess diagnostic")
			os.Exit(7)
		case "wrong":
			fmt.Println("0.70.0")
		case "extra":
			fmt.Println(requiredFRPVersion + " extra")
		default:
			os.Exit(8)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFRPVersionStartup(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := FRPConfig{Binary: binary, ServerAddr: "127.0.0.1", ServerPort: 7000,
		Token: strings.Repeat("a", 32), InsecureLocalTest: true, RuntimeDir: t.TempDir()}
	for _, tc := range []struct {
		name, mode, want string
	}{
		{"slow supported version", "slow", ""},
		{"nonzero exit", "exit", "could not execute successfully"},
		{"unsupported version", "wrong", "must report exactly version 0.71.0"},
		{"extra output rejected", "extra", "must report exactly version 0.71.0"},
		{"missing executable", "missing", "binary was not found"},
		{"startup timeout", "hang", "version check timed out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REMOTETOOL_TEST_FRP_VERSION", tc.mode)
			cfg := base
			if tc.mode == "missing" {
				cfg.Binary = filepath.Join(t.TempDir(), "missing-frpc.exe")
			}
			start := time.Now()
			f, err := NewFRP(cfg, "agent")
			if f != nil {
				t.Cleanup(func() { _ = f.Close() })
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if time.Since(start) <= 3*time.Second {
					t.Fatal("slow executable did not exercise the previous startup limit")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "private subprocess diagnostic") {
				t.Fatal("subprocess output leaked into diagnostic")
			}
			if tc.mode == "hang" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("timeout lost deadline cause: %v", err)
				}
				if time.Since(start) > frpStartupTimeout+5*time.Second {
					t.Fatal("version process was not canceled within the bounded startup budget")
				}
			}
		})
	}
}

func TestFRPVersionHonorsParentCancellation(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTETOOL_TEST_FRP_VERSION", "hang")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkFRPVersion(ctx, binary); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("canceled version check: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := checkFRPVersion(ctx, binary); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline not preserved: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("parent deadline extended by startup budget")
	}
}
