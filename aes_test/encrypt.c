//
//  encrypt.c
//  aes_test
//
//  Created by david on 16/8/10.
//  Copyright © 2016年 david. All rights reserved.
//

#include "string.h"
#include "encrypt.h"
#include "aes.h"
#include <stdlib.h>
#include <stdint.h>

static void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
    char          hex_str[]= "0123456789abcdef";
    unsigned int  i;
    
    *result = (char *)malloc(binsz * 2 + 1);
    (*result)[binsz * 2] = 0;
    
    if (!binsz)
        return;
    
    for (i = 0; i < binsz; i++)
    {
        (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }
}


static char* encrypt(char *msg)
{
    
    char input[32];
    memset(input, 0, 32);
    
    long n = strlen(msg) < 32 ? strlen(msg) : 32;
    
    strncpy(input, msg, n);
    
    uint8_t in[32];
    memset(in, 0, 32);
    
    for(int i = 0; i < n; i++){
        in[i] = (uint8_t)(input[i]);
    }
    
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    uint8_t buffer[64];
    memset(buffer, 0, 64);
    
    
    AES128_CBC_encrypt_buffer(buffer, in, (unsigned int)n, key, iv);
    
    //    AES128_ECB_encrypt(in, key, buffer);
    
    char *out;
    
    int outLength = n > 16 ? 32 : 16;
    
    bin_to_strhex(buffer, outLength, &out);
    
    return out;
}

static char* decrypt(char *msg)
{
    
    char input[64];
    memset(input, 0, 64);
    
    long n = strlen(msg);
    
    strncpy(input, msg, n);
    
    uint8_t in[32];
    memset(in, 0, 32);
    
    
    // 解密的时候， 将两位作为一位的uint_8
    for(int i = 0; i < n/2; i++){
        char *result = (char *)malloc(2 + 1 + 2);
        strcpy(result, "0x");
        strncat(result, &input[2*i], 2);
        in[i] = strtoul(result, NULL, 16);
    }
    
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t buffer[64];
    memset(buffer, 0, 64);
    
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    
    AES128_CBC_decrypt_buffer(buffer+0, in+0,  16, key, iv);
    AES128_CBC_decrypt_buffer(buffer+16, in+16, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+32, in+32, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+48, in+48, 16, 0, 0);
    
    //    AES128_ECB_decrypt(in, key, buffer);
    
    
    int length = 0;
    for (int i = 32 -1 ; i > 0; i--){
        if(buffer[i] != 0){
            length = i +1;
            break;
        }
    }
    
    if(length == 0 || length > n/2){
        length = (int)n/2;
    }
    
    char *result = (char *)malloc(length + 1);
    result[length] = 0;
    for(int i = 0 ; i < length ; i++){
        result[i] = (char)buffer[i];
    }
    
    return result;
}


int main(){
    
//    printf("%s\n", encrypt("abc"));
//    printf("%s\n", decrypt("9b23c121dffa1eb4cce25e1b98f7d3db"));
    
    printf("%s\n", encrypt("abc0"));
    printf("%s\n", decrypt("21cd8f576b63a35f1b1099c0fb47b52d"));
    
//    printf("%s\n", encrypt("ggg"));
//    printf("%s\n", decrypt("190ca4298c7ea8b06348384dc835f616"));
//    
//    printf("%s\n", encrypt("abc1234567890123"));
//    printf("%s\n", decrypt("cebbe1197fa95984d704d7d78db5d187"));
//    
//    
//    printf("%s\n", encrypt("af036026d51e425d9d17c6cae5d8465a"));
//    printf("%s\n", decrypt("cbbde9317c1d868b7af16543dc8fe4de97c971c9dc89d3cad0f45441118044d7"));
    
}