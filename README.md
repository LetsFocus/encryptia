# encryptia
This repository provides all the encryption and decryption algorithm in a easy to use fashion. It's like 
instant chapati where you buy them and just heat them.
implementing various AES encryption modes such as GCM, CTR, CFB, OFB, and ECB. The package also includes utilities for random key generation, base64 encoding/decoding, and more.

## Features

- **AES Encryption Modes:**
    - GCM (Galois/Counter Mode)
    - CTR (Counter Mode)
    - CFB (Cipher Feedback Mode)
    - OFB (Output Feedback Mode)
    - ECB (Electronic Codebook Mode)
- **Random Key and IV Generation**
- **Base64 Encoding/Decoding**
- **Factory Function to Create Cryptographer Based on Mode**

## Project Structure

```plaintext
.
├── pkg/
│   ├── asymmetric/
│   │   └── aes/
│   │       ├── aes_gcm.go
│   │       ├── aes_ctr.go
│   │       ├── aes_cfb.go
│   │       ├── aes_ofb.go
│   │       ├── aes_ecb.go
│   │       ├── aes_cryptographer.go
│   │       └── aes_factory.go
│   ├── symmetric/
│   │   └── (symmetric encryption files here)
│   ├── hashing/
│   │   └── (hashing algorithm files here)
│   ├── utils/
│   │   ├── utils.go
│   │   └── utils_test.go
├── examples/
│   └── main.go
├── README.md
└── go.mod

```

## Getting Started
#### Prerequisites
Go 1.18 or higher

## Installation
To install the package, Run the below command

```bash
go get github.com/LetsFocus/encryptia
```

## Usage
Encrypting and Decrypting Data
You can use the factory function to create the appropriate AES mode and perform encryption/decryption.

```azure
package main

import (
    "fmt"
    "log"
    "github.com/LetsFocus/encryptia/pkg/asymmetric/aes"
)

func main() {
    mode := "gcm"
    key := "thisis32bitlongpassphraseimusing!"

    cryptographer, err := aes.New(mode)
    if err != nil {
        log.Fatalf("Error creating cryptographer: %v", err)
    }

    plaintext := "Hello, World!"
    encrypted, err := cryptographer.Encrypt([]byte(plaintext), key)
    if err != nil {
        log.Fatalf("Error encrypting: %v", err)
    }

    fmt.Printf("Encrypted: %s\n", encrypted)

    decrypted, err := cryptographer.Decrypt(encrypted, key)
    if err != nil {
        log.Fatalf("Error decrypting: %v", err)
    }

    fmt.Printf("Decrypted: %s\n", decrypted)
}

```

## Design Patterns
This package uses the Factory Method design pattern to instantiate different AES cryptography modes based on the input mode string.

## Contributing
Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request.

## Contact
For any inquiries or issues, feel free to reach out at chdurga2001@gmail.com
