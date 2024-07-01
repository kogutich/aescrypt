# aescrypt

```text
Usage: aescrypt <command> [flags]

Tool for AES encryption/decryption.

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  encrypt    Encrypt data.
  decrypt    Decrypt data.

Run "aescrypt <command> --help" for more information on a command.
```

Examples:

```sh
echo "123" | aescrypt encrypt -p "my-password" -s "my-salt" --base64

# with files
aescrypt encrypt -p "my-password" -s "my-salt" < input.txt > encrypted
aescrypt decrypt -p "my-password" -s "my-salt" < encrypted > input_restored.txt
```

Installation:
```sh
go install -ldflags="-s -w" github.com/kogutich/aescrypt@latest
```
