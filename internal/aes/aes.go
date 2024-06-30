package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyLength     = 32
	keyIterations = 10_000
	bufSize       = 1024
)

type Config struct {
	Password []byte
	Salt     []byte
	Base64   bool
}

type Encrypter struct {
	cfg Config
}

func NewEncrypter(cfg Config) *Encrypter {
	return &Encrypter{cfg: cfg}
}

// Encrypt encrypts data from io.Reader and writes the ciphertext into io.Writer with optional Base64 encoding.
func (e *Encrypter) Encrypt(reader io.Reader, writer io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("encrypt error: %v", r)
			return
		}
	}()
	key := generateKey(e.cfg.Password, e.cfg.Salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv, err := randomSequence(aes.BlockSize)
	if err != nil {
		return err
	}
	if e.cfg.Base64 {
		enc := base64.NewEncoder(base64.StdEncoding, writer)
		defer enc.Close()
		writer = enc
	}
	if _, err = writer.Write(iv); err != nil {
		return err
	}
	stream := cipher.NewCBCEncrypter(block, iv)
	buf := make([]byte, bufSize)
	var notEmpty bool

	for {
		n, err := io.ReadFull(reader, buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if !notEmpty && n == 0 {
					return errors.New("empty data")
				}
				buf = addPadding(buf[:n], aes.BlockSize)
				stream.CryptBlocks(buf, buf)
				if _, err = writer.Write(buf); err != nil {
					return err
				}
				break
			}
			return err
		}
		notEmpty = true
		stream.CryptBlocks(buf, buf)
		if _, err = writer.Write(buf); err != nil {
			return err
		}
	}

	return nil
}

type Decrypter struct {
	cfg Config
}

func NewDecrypter(cfg Config) *Decrypter {
	return &Decrypter{cfg: cfg}
}

// Decrypt decrypts data with optional Base64 encoding from io.Reader and writes result into io.Writer.
func (d *Decrypter) Decrypt(reader io.Reader, writer io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decrypt error: %v", r)
			return
		}
	}()
	key := generateKey(d.cfg.Password, d.cfg.Salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := make([]byte, aes.BlockSize)
	if d.cfg.Base64 {
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	}
	if _, err := io.ReadFull(reader, iv); err != nil {
		return err
	}
	stream := cipher.NewCBCDecrypter(block, iv)
	prevBuf, currentBuf := make([]byte, bufSize), make([]byte, bufSize)
	firstRead := true

	for {
		n, err := io.ReadFull(reader, currentBuf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				buf := currentBuf[:n]
				if !firstRead {
					buf = slices.Concat(prevBuf, buf)
				} else if n == 0 {
					return errors.New("empty data")
				}
				stream.CryptBlocks(buf, buf)
				buf, err = removePadding(buf)
				if err != nil {
					return err
				}
				if _, err = writer.Write(buf); err != nil {
					return err
				}
				break
			}
			return err
		}
		if !firstRead {
			stream.CryptBlocks(prevBuf, prevBuf)
			if _, err = writer.Write(prevBuf); err != nil {
				return err
			}
		}
		firstRead = false
		prevBuf, currentBuf = currentBuf, prevBuf
	}

	return nil
}

func generateKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, keyIterations, keyLength, sha256.New)
}

func randomSequence(length int) ([]byte, error) {
	seq := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, seq); err != nil {
		return nil, err
	}
	return seq, nil
}

func addPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func removePadding(data []byte) ([]byte, error) {
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, errors.New("failed to remove padding")
	}
	return data[:len(data)-padding], nil
}
