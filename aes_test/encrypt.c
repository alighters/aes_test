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

static void set_char(unsigned char *bin, unsigned int binsz, char **result)
{
    unsigned int  i;
    
    *result = (char *)malloc(binsz + 1);
    (*result)[binsz] = 0;
    
    if (!binsz)
        return;
    
    for (i = 0; i < binsz; i++)
    {
//        (*result)[i] = strtoul(bin[i] & 0x0F, NULL, 16);
        (*result)[i] = (char)(bin[i] & 0x0F);
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
    
//    uint8_t buffer[16];
//    memset(buffer, 0, 16);
    
    
//    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
//        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    uint8_t buffer[64];
    memset(buffer, 0, 64);

    
//    AES128_CBC_encrypt_buffer(buffer, in, (unsigned int)n, key, iv);
    
    
    AES128_ECB_encrypt(in, key, buffer);
    
    char *out;
    
    bin_to_strhex(buffer, 16, &out);
    
    return out;
}

static char* decrypt(char *msg)
{
 
    char input[128];
    memset(input, 0, 128);
    
    long n = strlen(msg);
    
    strncpy(input, msg, n);

    uint8_t in[64];
    memset(in, 0, 64);
    
    
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
    
    AES128_ECB_decrypt(in, key, buffer);
    
    
    
    int length = 0;
    for ( int i = 64 -1 ; i > 0; i--){
        if(buffer[i] != 0){
            length = i +1;
            break;
        }
    }
    
    if(length == 0 || length > n){
        length = (int)n;
    }
    
    
    
    char *result = (char *)malloc(length + 1);
    result[length] = 0;
    for(int i = 0 ; i < length ; i++){
        result[i] = (char)buffer[i];
    }
    
//    set_char(buffer, (unsigned int)length, &result);
    
    return result;
}


int main(){
    
    printf("%s\n", encrypt("abc"));
    printf("%s\n", decrypt("0c795a305d8c09831d7f86a5143e8e09"));
    
    printf("%s\n", encrypt("ggg"));
    printf("%s\n", decrypt("842711a733cd4777a5ac3c657766fccb"));
  
}