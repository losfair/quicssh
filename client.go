package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
	"golang.org/x/net/context"
)

func client(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())

	config := &tls.Config{
		NextProtos: []string{"quicssh"},
	}

	if c.Bool("insecure-skip-verify") {
		config.InsecureSkipVerify = true
		log.Printf("WARNING: Skipping TLS certificate verification!")
	} else {
		hostname, _, err := net.SplitHostPort(c.String("addr"))
		if err != nil {
			return fmt.Errorf("failed to parse address: %w", err)
		}

		config.ServerName = hostname
		log.Printf("TLS certificate verification enabled.")
	}

	log.Printf("Dialing %q...", c.String("addr"))
	session, err := quic.DialAddr(ctx, c.String("addr"), config, &quic.Config{
		KeepAlivePeriod: time.Duration(c.Int("keep-alive-period-secs")) * time.Second,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("session close error: %v", err)
		}
	}()

	log.Printf("Opening stream sync...")
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}

	log.Printf("Piping stream with QUIC...")
	var wg sync.WaitGroup
	wg.Add(3)
	c1 := readAndWrite(ctx, stream, os.Stdout, &wg)
	c2 := readAndWrite(ctx, os.Stdin, stream, &wg)
	select {
	case err = <-c1:
		if err != nil {
			return err
		}
	case err = <-c2:
		if err != nil {
			return err
		}
	}
	cancel()
	wg.Wait()
	return nil
}
