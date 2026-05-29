#include "chacha20.hpp"
#include <cstdint>
#include <bit>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>

namespace ChaCha20{
cipher_parametrs knparametrs(){
    cipher_parametrs context;
    RAND_bytes((unsigned char*)context.key, sizeof(context.key));
    RAND_bytes((unsigned char*)context.nonce, sizeof(context.nonce));
    return context;
}

void initial_state(uint32_t* initial_state_matrix, cipher_parametrs key_and_nonce){
    const uint32_t constant[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t blockcount = 0;
    for(int i = 0, g = 0; i < 4; i++, g++)
        initial_state_matrix[i] = constant[g];
    for(int i = 4, g = 0; i < 12; i++, g++)
        initial_state_matrix[i] = key_and_nonce.key[g];
    initial_state_matrix[12] = blockcount;
    for(int i = 13, g = 0; i < 16; i++, g++)
        initial_state_matrix[i] = key_and_nonce.nonce[g];
}

void quater_round(uint32_t* chacha_matrix, int a, int b, int c, int d){
    chacha_matrix[a] += chacha_matrix[b]; chacha_matrix[d] ^= chacha_matrix[a]; chacha_matrix[d] = std::rotl(chacha_matrix[d], 16);
    chacha_matrix[c] += chacha_matrix[d]; chacha_matrix[b] ^= chacha_matrix[c]; chacha_matrix[b] = std::rotl(chacha_matrix[b], 12);
    chacha_matrix[a] += chacha_matrix[b]; chacha_matrix[d] ^= chacha_matrix[a]; chacha_matrix[d] = std::rotl(chacha_matrix[d], 8);
    chacha_matrix[c] += chacha_matrix[d]; chacha_matrix[b] ^= chacha_matrix[c]; chacha_matrix[b] = std::rotl(chacha_matrix[b], 7);
}

void block_function(uint32_t* initial_state_matrix, uint8_t* keystream){
    uint32_t cypher_matrix[16];
    for(int i = 0; i < 16; i++)
        cypher_matrix[i] = initial_state_matrix[i];

    for(int i = 0; i < 10; i++){
        quater_round(cypher_matrix, 0, 4, 8, 12);
        quater_round(cypher_matrix, 1, 5, 9, 13);
        quater_round(cypher_matrix, 2, 6, 10, 14);
        quater_round(cypher_matrix, 3, 7, 11, 15);
        quater_round(cypher_matrix, 0, 5, 10, 15);
        quater_round(cypher_matrix, 1, 6, 11, 12);
        quater_round(cypher_matrix, 2, 7, 8, 13);
        quater_round(cypher_matrix, 3, 4, 9, 14);
    }

    for(int i = 0; i < 16; i++)
        cypher_matrix[i] += initial_state_matrix[i];
    
    for(int i = 0; i < 16; i++){
        keystream[4*i+0] = (cypher_matrix[i] >> 0) & 0xFF;
        keystream[4*i+1] = (cypher_matrix[i] >> 8) & 0xFF;
        keystream[4*i+2] = (cypher_matrix[i] >> 16) & 0xFF;
        keystream[4*i+3] = (cypher_matrix[i] >> 24) & 0xFF;
    }
}

Result encrypt(std::string text){
    Result result;
    uint32_t chacha_matrix[16];
    uint8_t keystream[64];
    cipher_parametrs key_and_nonce;
    key_and_nonce = knparametrs();
    for(int i = 0; i < 8; i++)
        result.key_value[i] = key_and_nonce.key[i];
    for(int i = 0; i < 3; i++)
        result.nonce_value[i] = key_and_nonce.nonce[i];
    initial_state(chacha_matrix, key_and_nonce);
    result.ciphertext.resize(text.size());
    for(size_t i = 0; i < text.size(); i += (size_t)64){
        block_function(chacha_matrix, keystream);
        size_t block_size = std::min(text.size() - i, (size_t)64);
        for(size_t g = 0; g < block_size; g++)
            result.ciphertext[i+g] = text[i+g] ^ keystream[g];
        chacha_matrix[12]++;
    }
    return result;
}

std::string decrypt(Result data_to_decrypt){
    std::string decrypted_message;
    decrypted_message.resize(data_to_decrypt.ciphertext.size());
    uint32_t chacha_matrix[16];
    uint8_t keystream[64];
    cipher_parametrs initial_parametrs;
    for(int i = 0; i < 8; i++)
        initial_parametrs.key[i] = data_to_decrypt.key_value[i];
    for(int i = 0; i < 3; i++)
        initial_parametrs.nonce[i] = data_to_decrypt.nonce_value[i];
    initial_state(chacha_matrix, initial_parametrs);
    for(size_t i = 0; i < data_to_decrypt.ciphertext.size(); i += (size_t)64){
        block_function(chacha_matrix, keystream);
        size_t block_size = std::min(data_to_decrypt.ciphertext.size() - i, (size_t)64);
        for(size_t g = 0; g < block_size; g++)
            decrypted_message[i+g] = data_to_decrypt.ciphertext[i+g] ^ keystream[g];
        chacha_matrix[12]++; 
    }
    return decrypted_message;
}
}