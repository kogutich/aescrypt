package cmd

import (
	"os"

	"github.com/kogutich/aescrypt/internal/aes"
)

type Decrypt struct {
	Password string `help:"Password."                required:""   short:"p"`
	Salt     string `help:"Optional salt."           short:"s"`
	Base64   bool   `help:"Input is base64 encoded." name:"base64"`
}

func (d *Decrypt) Run() error {
	dec := aes.NewDecrypter(aes.Config{
		Password: []byte(d.Password),
		Salt:     []byte(d.Salt),
		Base64:   d.Base64,
	})
	return dec.Decrypt(os.Stdin, os.Stdout)
}
