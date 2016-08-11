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
        (*result)[i] = bin[i] & 0x0F;
    }
}



static char* encrypt(char *msg)
{
    
    char input[32];
    memset(input, 0, 32);
    
    long n = strlen(msg) < 32 ? strlen(msg) : 32;
    
    strncpy(input, msg, n);
    input[n] = '\0';
    uint8_t in[16];
    memset(in, 0, 16);
   

    
    for(int i = 0; i < 16; i++){
        char *result = (char *)malloc(2 + 1 + 2);
        strcpy(result, "0x");
        strncat(result, &input[2*i], 2);
        in[i] = strtoul(result, NULL, 16);
    }

    
    
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    uint8_t buffer[16];
    memset(buffer, 0, 16);
    
    
    AES128_ECB_encrypt(in, key, buffer);
    
    char *result;
    
    unsigned int length = n < 16 ? (unsigned int)n : 16;
    
    bin_to_strhex(buffer, length, &result);
    
    return result;
}

static char* decrypt(char *msg)
{
 
    char input[32];
    memset(input, 0, 32);
    
    long n = strlen(msg) < 32 ? strlen(msg) : 32;
    
    strncpy(input, msg, n);
    input[n] = '\0';
    uint8_t in[16];
    memset(in, 0, 16);
    
    
    
    for(int i = 0; i < n/2; i++){
        char *result = (char *)malloc(2 + 1 + 2);
        strcpy(result, "0x");
        strncat(result, &input[2*i], 2);
        in[i] = strtoul(result, NULL, 16);
    }
    
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t buffer[16];
    memset(buffer, 0, 16);
    
    AES128_ECB_decrypt(in, key, buffer);
    
    char *result;
    for(int i = 0; i < n/2; i ++ ){
        printf("%.2x", buffer[i]);
    }
    printf("\n");
    
//    set_char(buffer, (unsigned int)(n/2), &result);
    
    bin_to_strhex(buffer, (unsigned int)n/2, &result);
    
    return result;
}


int main(){
    
    
    
//    printf("%s\n", encrypt("0a0b0c01020304050607080900010203"));
//    printf("%s\n", decrypt("9ae0de5e82266daaa589570a628ab7cf"));
    

//    printf("%s\n", encrypt("6bc1bee22e409f96e93d7e117393172a"));
//    printf("%s\n", decrypt("3ad77bb40d7a3660a89ecaf32466ef97"));
    
    printf("%s\n", encrypt("abc"));
    printf("%s\n", decrypt("c27d3d"));
}