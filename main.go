package main

import (
	"github.com/alecthomas/kong"
	"github.com/kogutich/aescrypt/internal/cmd"
)

type App struct {
	Encrypt cmd.Encrypt `cmd:"encrypt" help:"Encrypt data."`
	Decrypt cmd.Decrypt `cmd:"decrypt" help:"Decrypt data."`
}

func main() {
	ctx := kong.Parse(
		&App{},
		kong.Name("aescrypt"),
		kong.Description("Tool for AES encryption/decryption."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
	)
	if err := ctx.Run(); err != nil {
		ctx.FatalIfErrorf(err)
	}
}
