# ChaCha20 Implementation in C++

## Description
An implementation of Chacha20 stream cipher in C++ in accordance with RFC 8439 standard.

>[!NOTE]
>This implementation was made primarily with educational purpose. For enterprise purpose it is highly recommended to use industry-approved cryptographic libraries.

## Key Features
+ **Automated Context Generation:** Automatically creates the cryptographic context(256-bit key and 96-bit nonce) using OpenSSL's CSPRNG.
+ **High Level Api:** Provides a clean, easy-to-use C++ wrapper(encrypt/decrypt) over the low level cryptographic block function.
+ **Custom Cipher Core:** Core mathematic transformations(quater rounds, matrix state management, block function) are implemented entirely from scratch relying exclusively on CSPRNG provided by OpenSSL library.

## Prerequisits
1. ***[OpenSSL](https://openssl-library.org/) library.***
2. ***C++20 or C++23 compatible compiler.***

## Usage
```cpp
std::string text = "Thanks for supporting me!";
ChaCha20::Result data = ChaCha20::encrypt(text);
std::string decrypted_text = ChaCha20::decrypt(data);
std::cout << "Decrypted: " << decrypted_text << "\n";
```

