package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func readConfig(path string, out any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}
func serve(ctx context.Context, s *http.Server, cert, key string) error {
	ch := make(chan error, 1)
	go func() {
		if cert != "" {
			ch <- s.ListenAndServeTLS(cert, key)
		} else {
			ch <- s.ListenAndServe()
		}
	}()
	select {
	case e := <-ch:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.Shutdown(c)
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "remotetool:", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: remotetool server|agent|admin -config FILE")
	}
	role := os.Args[1]
	f := flag.NewFlagSet(role, flag.ContinueOnError)
	path := f.String("config", "config.json", "private JSON configuration")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if role == "server" {
		var c ServerConfig
		if e := readConfig(*path, &c); e != nil {
			return e
		}
		if c.Listen == "" {
			c.Listen = "127.0.0.1:8080"
		}
		host, _, e := net.SplitHostPort(c.Listen)
		if e != nil {
			return e
		}
		ip := net.ParseIP(host)
		if (ip == nil || !ip.IsLoopback()) && (c.TLSCert == "" || c.TLSKey == "") {
			return errors.New("non-loopback server requires tlsCert and tlsKey")
		}
		r, e := NewRegistry(c)
		if e != nil {
			return e
		}
		fmt.Println("Central registry listening on", c.Listen)
		return serve(ctx, &http.Server{Addr: c.Listen, Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, c.TLSCert, c.TLSKey)
	}
	if role != "agent" && role != "admin" {
		return errors.New("role must be server, agent, or admin")
	}
	var c ClientConfig
	if e := readConfig(*path, &c); e != nil {
		return e
	}
	r, e := NewRunner(c, role)
	if e != nil {
		return e
	}
	defer r.FRP.Close()
	if role == "agent" {
		r.Run(ctx)
		return nil
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8181"
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || host != "127.0.0.1" {
		return errors.New("admin UI must bind 127.0.0.1")
	}
	token := randomHex(24)
	fmt.Printf("Open http://%s and enter temporary UI token:\n%s\n", c.Listen, token)
	workerDone := make(chan struct{})
	go func() { r.Run(ctx); close(workerDone) }()
	e = serve(ctx, &http.Server{Addr: c.Listen, Handler: r.UI(token, c.Listen), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}, "", "")
	cancel()
	<-workerDone
	return e
}
