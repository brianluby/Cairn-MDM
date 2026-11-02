package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"os"
	"path/filepath"
)

func pushcertDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Storage.Path), "pushcert")
}

func runPushcertRequest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert request", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "configuration path")
	email := fs.String("email", "", "registered mdmcert.download email")
	country := fs.String("country", "US", "CSR country code")
	cn := fs.String("cn", "", "CSR common name")
	resume := fs.String("resume", "", "resubmit an existing request ID with the same keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	m := push.RequestManager{Root: filepath.Join(pushcertDir(cfg), "requests")}
	var r push.Request
	if *resume != "" {
		if *email != "" || *cn != "" {
			return fmt.Errorf("resume uses the original email and CSR; omit -email and -cn")
		}
		r, err = m.Load(*resume)
	} else {
		r, err = m.Create(*email, *country, *cn)
	}
	if err != nil {
		return err
	}
	dir, _ := m.Directory(r.ID)
	fmt.Printf("Request ID: %s\nPrivate request directory: %s\n", r.ID, dir)
	if err = m.Submit(ctx, r.ID); err != nil {
		return err
	}
	fmt.Printf("Request submitted. Check %s for the encrypted attachment.\n", r.Email)
	fmt.Printf("Decrypt: cairn pushcert decrypt -config %q -request-id %s -in <attachment.p7>\n", *cfgPath, r.ID)
	fmt.Printf("Renew the existing entry in Apple's portal when renewing a live fleet.\n")
	fmt.Printf("Keep %s; it matches Apple's eventual certificate.\n", filepath.Join(dir, "push.key"))
	return nil
}

func runPushcertDecrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert decrypt", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "configuration path")
	in := fs.String("in", "", "signed .p7 attachment")
	out := fs.String("out", "", "output path (must not already exist)")
	id := fs.String("request-id", "", "request ID printed by pushcert request")
	legacy := fs.Bool("legacy", false, "use the pre-request-ID flat directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || (*id == "") == (!*legacy) {
		return fmt.Errorf("provide -in and exactly one of -request-id or -legacy")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	stat, err := os.Stat(*in)
	if err != nil {
		return err
	}
	if stat.Size() > 1<<20 {
		return fmt.Errorf("attachment exceeds 1 MiB")
	}
	attachment, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	dir := pushcertDir(cfg)
	var content []byte
	if *legacy {
		content, err = push.DecryptRequestDirectory(dir, attachment)
	} else {
		m := push.RequestManager{Root: filepath.Join(dir, "requests")}
		content, err = m.Decrypt(*id, attachment)
		dir, _ = m.Directory(*id)
	}
	if err != nil {
		return err
	}
	if *out == "" {
		*out = filepath.Join(dir, "push_request.plist")
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Printf("Apple-ready request: %s\nFor renewal, use Renew on the existing Apple portal entry.\n", *out)
	return nil
}
