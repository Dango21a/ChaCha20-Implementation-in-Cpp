#pragma once
#include <cstdint>
#include <vector>
#include <string>
namespace ChaCha20{
    struct Result{
        std::vector<uint8_t> ciphertext;
        uint32_t key_value[8];
        uint32_t nonce_value[3];
    };
    struct cipher_parametrs{
        uint32_t key[8];
        uint32_t nonce[3];
    };
    Result encrypt(std::string text);
    std::string decrypt(Result data_to_decrypt);
}