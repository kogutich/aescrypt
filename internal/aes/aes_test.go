package aes

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufSize(t *testing.T) {
	require.Greater(t, bufSize, aes.BlockSize)
	require.Zero(t, bufSize%aes.BlockSize)
}

func TestCryptRaw(t *testing.T) {
	cfg := Config{
		Password: []byte("my_secure_password"),
		Salt:     []byte("my_unique_salt"),
		Base64:   false,
	}
	e, d := NewEncrypter(cfg), NewDecrypter(cfg)
	for l := 1; l <= 5000; l++ {
		for i := 0; i < 10; i++ {
			t.Run(fmt.Sprintf("%d_%d", l, i), func(t *testing.T) {
				data, err := randomSequence(l)
				require.NoError(t, err)
				dataReader := bytes.NewReader(data)
				var encryptBuf, decryptBuf bytes.Buffer
				require.NoError(t, e.Encrypt(dataReader, &encryptBuf))
				require.NotEqual(t, data, encryptBuf.Bytes())
				require.NoError(t, d.Decrypt(bytes.NewReader(encryptBuf.Bytes()), &decryptBuf))
				require.Equal(t, data, decryptBuf.Bytes())
			})
		}
	}
}

func TestCryptBase64(t *testing.T) {
	cfg := Config{
		Password: []byte("my_other_secure_password"),
		Salt:     []byte("my_other_unique_salt"),
		Base64:   true,
	}
	e, d := NewEncrypter(cfg), NewDecrypter(cfg)
	for l := 1; l <= 5000; l++ {
		for i := 0; i < 10; i++ {
			t.Run(fmt.Sprintf("%d_%d", l, i), func(t *testing.T) {
				data, err := randomSequence(l)
				require.NoError(t, err)
				dataReader := bytes.NewReader(data)
				var encryptBuf, decryptBuf bytes.Buffer
				require.NoError(t, e.Encrypt(dataReader, &encryptBuf))
				require.NotEqual(t, data, encryptBuf.Bytes())
				require.NoError(t, d.Decrypt(bytes.NewReader(encryptBuf.Bytes()), &decryptBuf))
				require.Equal(t, data, decryptBuf.Bytes())
			})
		}
	}
}
