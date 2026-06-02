// Command peipkg-build builds .peipkg packages from a recipe + source tree
// (the `build` subcommand) or from a pre-resolved manifest + staged tree
// (the `pack` subcommand).
//
// Most users invoke `build`. `pack` exists for exotic builds (kernel,
// glibc, etc.) where the recipe abstraction gets in the way and the caller
// hands the tool a finished staged tree.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/peios/peipkg-build/internal/binsign"
	"github.com/peios/peipkg-build/internal/builder"
	"github.com/peios/peipkg-build/internal/manifest"
	"github.com/peios/peipkg-build/internal/pack"
	"github.com/peios/peipkg-build/internal/recipe"
	"github.com/peios/peipkg-build/internal/signature"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	sub, args := os.Args[1], os.Args[2:]

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch sub {
	case "pack":
		err = cmdPack(args)
	case "build":
		err = cmdBuild(ctx, args)
	case "binary-sign":
		err = cmdBinarySign(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "peipkg-build: unknown subcommand %q\n\n", sub)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "peipkg-build:", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage: peipkg-build <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  build         run a recipe end-to-end and emit one .peipkg per [[package]]")
	fmt.Fprintln(w, "  pack          emit one .peipkg from a manifest.json + staged tree")
	fmt.Fprintln(w, "  binary-sign   embed a .peios.sig (PIP) signature into an ELF binary in place")
}

// cmdBinarySign implements the `binary-sign` subcommand: a low-level entry
// point that embeds a Peios binary signature (the .peios.sig ELF section the
// kernel verifies at exec for PIP trust) into an ELF in place. This is
// separate from package signing; see peios/binary-signing-design.md.
func cmdBinarySign(args []string) error {
	fs := flag.NewFlagSet("binary-sign", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-build binary-sign --in PATH --key PATH")
		fs.PrintDefaults()
	}
	inPath := fs.String("in", "", "path to the ELF binary to sign in place (required)")
	keyPath := fs.String("key", "", "path to the Ed25519 binary-signing private key (PEM or 32-byte raw seed) (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *keyPath == "" {
		fs.Usage()
		return fmt.Errorf("--in and --key are both required")
	}

	priv, err := signature.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signer, err := binsign.NewKeySigner(priv)
	if err != nil {
		return err
	}
	return binsign.SignELF(*inPath, signer)
}

// cmdPack implements the `pack` subcommand: a low-level entry point that
// takes a fully-resolved manifest and a staged payload tree and emits one
// .peipkg. The build provenance (timestamp, farm_id, source_ref) is read
// from the manifest's `build` object — the caller is responsible for putting
// it there before invoking pack.
func cmdPack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-build pack --manifest PATH --staged DIR --out PATH")
		fs.PrintDefaults()
	}

	manifestPath := fs.String("manifest", "", "path to a fully-resolved manifest.json (required)")
	stagedPath := fs.String("staged", "", "path to the staged payload tree (required)")
	outPath := fs.String("out", "", "path to the output .peipkg (required)")
	signKeyPath := fs.String("sign-key", "", "path to an Ed25519 private key (PEM or 32-byte raw seed); empty = unsigned package")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *stagedPath == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("--manifest, --staged, and --out are all required")
	}

	manifestBytes, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var m manifest.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	var signKey ed25519.PrivateKey
	if *signKeyPath != "" {
		signKey, err = signature.LoadPrivateKey(*signKeyPath)
		if err != nil {
			return err
		}
	}

	out, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	if err := pack.Pack(pack.Input{
		StagedRoot: *stagedPath,
		Manifest:   m,
		SignKey:    signKey,
		Out:        out,
	}); err != nil {
		_ = out.Close()
		_ = os.Remove(*outPath)
		return err
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	return nil
}

// cmdBuild implements the `build` subcommand: parse recipe, run build.sh,
// partition the staged tree across [[package]] stanzas, emit one .peipkg
// per stanza into --out.
func cmdBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-build build [flags]")
		fs.PrintDefaults()
	}

	recipePath := fs.String("recipe", "", "path to peipkg.toml (required)")
	sourceDir := fs.String("source", "", "path to the source checkout (required)")
	version := fs.String("version", "", "package version (required, e.g. 1.3.2-1)")
	sourceRef := fs.String("source-ref", "", "machine-resolvable reference to build inputs (required)")
	farmID := fs.String("farm-id", "", "build farm identifier (required)")
	timestamp := fs.String("timestamp", "", "RFC 3339 UTC build timestamp ending with 'Z' (required)")
	outDir := fs.String("out", "", "output directory for .peipkg files (required, created if missing)")
	signKeyPath := fs.String("sign-key", "", "path to an Ed25519 private key (PEM or 32-byte raw seed); empty = unsigned packages")

	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, val := range map[string]string{
		"--recipe":     *recipePath,
		"--source":     *sourceDir,
		"--version":    *version,
		"--source-ref": *sourceRef,
		"--farm-id":    *farmID,
		"--timestamp":  *timestamp,
		"--out":        *outDir,
	} {
		if val == "" {
			fs.Usage()
			return fmt.Errorf("%s is required", name)
		}
	}

	r, err := recipe.Load(*recipePath)
	if err != nil {
		return err
	}

	recipeAbs, err := filepath.Abs(*recipePath)
	if err != nil {
		return fmt.Errorf("resolve --recipe: %w", err)
	}
	buildScript := filepath.Join(filepath.Dir(recipeAbs), r.Meta.BuildScript)

	var signKey ed25519.PrivateKey
	if *signKeyPath != "" {
		signKey, err = signature.LoadPrivateKey(*signKeyPath)
		if err != nil {
			return err
		}
	}

	res, err := builder.Build(ctx, builder.Config{
		Recipe:      r,
		BuildScript: buildScript,
		SourceDir:   *sourceDir,
		Version:     *version,
		SourceRef:   *sourceRef,
		FarmID:      *farmID,
		Timestamp:   *timestamp,
		OutDir:      *outDir,
		SignKey:     signKey,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	})
	if err != nil {
		return err
	}

	for _, p := range res.Outputs {
		fmt.Println(p)
	}
	return nil
}
