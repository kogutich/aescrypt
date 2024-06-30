package cmd

import (
	"os"

	"github.com/kogutich/aescrypt/internal/aes"
)

type Encrypt struct {
	Password string `help:"Password."                required:""   short:"p"`
	Salt     string `help:"Optional salt."           short:"s"`
	Base64   bool   `help:"Encode output in base64." name:"base64"`
}

func (e *Encrypt) Run() error {
	enc := aes.NewEncrypter(aes.Config{
		Password: []byte(e.Password),
		Salt:     []byte(e.Salt),
		Base64:   e.Base64,
	})
	return enc.Encrypt(os.Stdin, os.Stdout)
}
