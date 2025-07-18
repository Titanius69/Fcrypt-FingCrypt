# Fcrypt - Quantum-Resistant Cryptography Library

A C++ library implementing quantum-resistant cryptographic algorithms based on the Module Learning With Errors (Module-LWE) problem, inspired by the Kyber post-quantum cryptography standard.

## Features

- **Quantum-Resistant Encryption**: Uses Module-LWE for encryption that is believed to be secure against quantum computer attacks
- **Memory-Hard Hashing**: Argon2-inspired hash function with enhanced Blake2b-like mixing
- **Message Authentication**: Built-in MAC (Message Authentication Code) for integrity verification
- **Secure Random Number Generation**: ChaCha20-based cryptographically secure PRNG
- **Error Detection**: Robust decoding with tampering detection
- **Header-Only**: Single header file for easy integration

## Security Properties

- **Post-Quantum Security**: Resistant to attacks by quantum computers
- **Authenticated Encryption**: Provides both confidentiality and integrity
- **Memory-Hard Functions**: Resistant to brute-force attacks using specialized hardware
- **Secure Key Generation**: Cryptographically secure random key generation
- **Tampering Detection**: Detects and prevents decryption of modified ciphertexts

## Visual Studio 2022 Setup

### System Requirements

- **Visual Studio 2022**: Version 17.0 or later
- **Windows SDK**: 10.0.19041.0 or later
- **MSVC Toolset**: v143 or later
- **C++ Standard**: C++20 (ISO C++20 Standard)

### Project Configuration

1. **Create New Project**:
   - Open Visual Studio 2022
   - File → New → Project
   - Select "Console App" (C++)
   - Set Language to C++

2. **Configure Project Properties**:
   - Right-click project → Properties
   - Configuration: All Configurations
   - Platform: x64 (recommended)

3. **Set C++ Standard**:
   - Go to Configuration Properties → C/C++ → Language
   - Set "C++ Language Standard" to "ISO C++20 Standard (/std:c++20)"

4. **Optimization Settings**:
   - Configuration Properties → C/C++ → Optimization
   - For Release: Set "Optimization" to "Maximum Optimization (Favor Speed) (/O2)"
   - For Debug: Set "Optimization" to "Disabled (/Od)"

### Adding fcrypt to Your Project

1. **Include Header**:
   - Copy `fcrypt.hpp` to your project directory
   - Add `#include "fcrypt.hpp"` to your source files

2. **Sample main.cpp**:
   ```cpp
   #include "fcrypt.hpp"
   #include <iostream>
   #include <string>

   using namespace fcrypt;

   int main() {
       try {
           // Generate a key pair
           auto key_pair = generate_key_pair();
           
           // Encrypt a message
           std::string message = "Hello, quantum-resistant world!";
           std::vector<uint8_t> data(message.begin(), message.end());
           
           auto ciphertext = encrypt(key_pair, data);
           std::cout << "Message encrypted successfully!" << std::endl;
           
           // Decrypt the message
           auto decrypted = decrypt(key_pair, ciphertext);
           std::string decrypted_message(decrypted.begin(), decrypted.end());
           
           std::cout << "Decrypted: " << decrypted_message << std::endl;
           
       } catch (const CryptoException& e) {
           std::cerr << "Crypto error: " << e.what() << std::endl;
       }
       
       return 0;
   }
   ```

### Build Configuration

#### Debug Configuration
- **Runtime Library**: Multi-threaded Debug DLL (/MDd)
- **Optimization**: Disabled (/Od)
- **Debug Information**: Program Database (/Zi)
- **Preprocessor Definitions**: `_DEBUG`

#### Release Configuration
- **Runtime Library**: Multi-threaded DLL (/MD)
- **Optimization**: Maximum Optimization (/O2)
- **Inline Function Expansion**: Any Suitable (/Ob2)
- **Preprocessor Definitions**: `NDEBUG`

### Performance Optimization for VS2022

1. **Compiler Flags**:
   - Enable intrinsic functions: `/Oi`
   - Whole program optimization: `/GL` (Release only)
   - Link-time code generation: `/LTCG` (Release only)

2. **Platform Settings**:
   - Target platform: x64 (better performance than x86)
   - Enable AVX2 instructions: `/arch:AVX2` (if supported)

3. **Memory Settings**:
   - Increase heap size if needed: `/HEAP:8388608` (8MB)
   - Stack size: `/STACK:8388608` (8MB)

### Building the Project

1. **Using Visual Studio IDE**:
   - Press `F7` or Build → Build Solution
   - For Release: Set Solution Configuration to "Release"
   - For Debug: Set Solution Configuration to "Debug"

2. **Using Developer Command Prompt**:
   ```cmd
   # Debug build
   cl /std:c++20 /EHsc /MDd /Od /Zi main.cpp /Fe:fcrypt_debug.exe

   # Release build
   cl /std:c++20 /EHsc /MD /O2 /GL main.cpp /Fe:fcrypt_release.exe /link /LTCG
   ```

### Troubleshooting

#### Common Issues

1. **C++20 Standard Not Available**:
   - Update Visual Studio 2022 to latest version
   - Install latest Windows SDK

2. **Linker Errors**:
   - Ensure target platform is x64
   - Check runtime library settings match

3. **Performance Issues**:
   - Use Release configuration for performance testing
   - Enable optimization flags
   - Consider using 64-bit build

#### IntelliSense Configuration

Add to `.vscode/c_cpp_properties.json` if using VS Code:
```json
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": ["${workspaceFolder}/**"],
            "defines": ["_DEBUG", "_CONSOLE"],
            "windowsSdkVersion": "10.0.19041.0",
            "compilerPath": "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.30.30705/bin/Hostx64/x64/cl.exe",
            "cStandard": "c17",
            "cppStandard": "c++20",
            "intelliSenseMode": "windows-msvc-x64"
        }
    ]
}
```

## API Reference

### Core Functions

#### `KeyPair generate_key_pair()`
Generates a new key pair for encryption/decryption operations.

**Returns**: `KeyPair` structure containing public and private keys

#### `Ciphertext encrypt(const KeyPair& public_key, const std::vector<uint8_t>& message)`
Encrypts a message using the provided key pair.

**Parameters**:
- `public_key`: Key pair containing public key
- `message`: Message to encrypt (max 32 bytes)

**Returns**: `Ciphertext` structure containing encrypted data and MAC

**Throws**: `CryptoException` if message is empty or too long

#### `std::vector<uint8_t> decrypt(const KeyPair& private_key, const Ciphertext& ciphertext)`
Decrypts a ciphertext using the provided key pair.

**Parameters**:
- `private_key`: Key pair containing private key
- `ciphertext`: Ciphertext to decrypt

**Returns**: Decrypted message as byte vector

**Throws**: `CryptoException` if decryption fails or MAC verification fails

### Hashing Functions

#### `std::array<uint8_t, 32> hash_data(const std::vector<uint8_t>& data)`
Computes a cryptographic hash of the input data.

#### `std::array<uint8_t, 32> generate_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key)`
Generates a Message Authentication Code.

#### `bool verify_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key, const std::array<uint8_t, 32>& mac)`
Verifies a Message Authentication Code.

## Technical Details

### Algorithm Parameters

- **Polynomial degree (n)**: 256
- **Module dimension (k)**: 3
- **Modulus (q)**: 3329 (prime)
- **Error distribution**: Centered binomial with η = 3
- **Memory usage**: 8 MB for memory-hard hashing
- **Hash iterations**: 20 rounds of mixing

### Security Level

The library is designed to provide approximately 128-bit security against classical computers and resistance against quantum attacks.

### Memory Requirements

- **Key pair**: ~24 KB
- **Ciphertext**: ~24 KB + message length
- **Hash function**: 8 MB temporary memory during hashing

## Limitations

- **Message size**: Maximum 32 bytes per encryption operation
- **Performance**: Quantum-resistant algorithms are computationally intensive
- **Memory usage**: High memory requirements for security
- **Experimental**: This is an educational/experimental implementation

## Security Warnings

⚠️ **Important Security Notice**:

1. **Experimental Implementation**: This library is for educational and experimental purposes
2. **Not Production Ready**: Do not use in production environments
3. **Security Audit Required**: Requires thorough security review before any real-world use
4. **Constant-Time Operations**: Implementation may be vulnerable to timing attacks
