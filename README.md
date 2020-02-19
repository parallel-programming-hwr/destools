# destools

Tools to encrypt and brute force decrypt with des.

## Usage

```sh
USAGE:
    destools <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    create-dictionary    Create a dictionary rainbow-table from a txt file
    decrypt              Decrypt a DES encoded file
    encrypt              Encrypt a file with des
    help                 Prints this message or the help of the given subcommand(s)
```

## Example

```shell script
# Encrypt test.txt to test.des
destools encrypt -i test.txt -o test.des --checksum-file test.sha256

# Create a rainbow table from passwords.txt
destools create-dictionary -i passwords.txt -o dictionary.csv

# Decrypt test.des
destools decrypt -i test.des -o decrypted.txt

# Try to brute force dercrypt test.des
destools decrypt -i test.des -o decrypted.txt -d dictionary.csv --checksum-file test.sha256
```