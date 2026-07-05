#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

// SHA-256 常量（前 64 个素数的立方根的小数部分）
static const uint32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// 循环移位操作
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHR(x,n) ((x)>>(n))
// SHA-256 逻辑函数
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x,3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x,10))

//// SHA-256 上下文结构
//typedef struct {
//    uint32 state[8];        // 哈希状态
//    uint64 bitcount;        // 消息位长度
//    uint8 buffer[64];       // 消息块缓冲区
//    int buffer_len;         // 缓冲区当前长度
//} SHA256_CTX;
//
//// 初始化 SHA-256 上下文
//void SHA256_Init(SHA256_CTX* ctx) {
//    // 初始化哈希值（前 8 个素数的平方根的小数部分）
//    ctx->state[0] = 0x6a09e667;
//    ctx->state[1] = 0xbb67ae85;
//    ctx->state[2] = 0x3c6ef372;
//    ctx->state[3] = 0xa54ff53a;
//    ctx->state[4] = 0x510e527f;
//    ctx->state[5] = 0x9b05688c;
//    ctx->state[6] = 0x1f83d9ab;
//    ctx->state[7] = 0x5be0cd19;
//
//    ctx->bitcount = 0;
//    ctx->buffer_len = 0;
//}
//
//// 处理单个 512 位消息块
//void SHA256_Transform(SHA256_CTX* ctx, const uint8 data[64]) {
//    uint32 a, b, c, d, e, f, g, h, T1, T2;
//    uint32 m[64];
//    int i;
//
//    // 将消息块转换为 32 位字
//    for (i = 0; i < 16; i++) {
//        m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
//            (data[i * 4 + 2] << 8) | data[i * 4 + 3];
//    }
//
//    // 扩展消息块为 64 个字
//    for (i = 16; i < 64; i++) {
//        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
//    }
//
//    // 初始化工作变量
//    a = ctx->state[0];
//    b = ctx->state[1];
//    c = ctx->state[2];
//    d = ctx->state[3];
//    e = ctx->state[4];
//    f = ctx->state[5];
//    g = ctx->state[6];
//    h = ctx->state[7];
//
//    // 64 轮压缩函数
//    for (i = 0; i < 64; i++) {
//        T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + m[i];
//        T2 = Sigma0(a) + Maj(a, b, c);
//        h = g;
//        g = f;
//        f = e;
//        e = d + T1;
//        d = c;
//        c = b;
//        b = a;
//        a = T1 + T2;
//    }
//
//    // 将结果添加到当前哈希值
//    ctx->state[0] += a;
//    ctx->state[1] += b;
//    ctx->state[2] += c;
//    ctx->state[3] += d;
//    ctx->state[4] += e;
//    ctx->state[5] += f;
//    ctx->state[6] += g;
//    ctx->state[7] += h;
//}
//
//// 更新 SHA-256 哈希计算
//void SHA256_Update(SHA256_CTX* ctx, const uint8* data, size_t len) {
//    size_t i, rem;
//
//    // 更新消息位长度
//    ctx->bitcount += len * 8;
//
//    // 处理已有的缓冲区
//    rem = ctx->buffer_len;
//    if (rem) {
//        size_t copy_len = (len < (64 - rem)) ? len : (64 - rem);
//        memcpy(ctx->buffer + rem, data, copy_len);
//        ctx->buffer_len += copy_len;
//
//        if (ctx->buffer_len == 64) {
//            SHA256_Transform(ctx, ctx->buffer);
//            ctx->buffer_len = 0;
//        }
//
//        data += copy_len;
//        len -= copy_len;
//    }
//
//    // 处理剩余数据块
//    for (i = 0; i + 64 <= len; i += 64) {
//        SHA256_Transform(ctx, data + i);
//    }
//
//    // 将剩余数据存入缓冲区
//    rem = len - i;
//    if (rem) {
//        memcpy(ctx->buffer, data + i, rem);
//        ctx->buffer_len = rem;
//    }
//}
//
//// 完成 SHA-256 哈希计算并输出结果
//void SHA256_Final(uint8 digest[32], SHA256_CTX* ctx) {
//    int i;
//    uint8 final_block[64] = { 0 };
//    int pad_len;
//    uint64 bit_len = ctx->bitcount;
//
//    // 计算填充长度
//    pad_len = 64 - ((ctx->buffer_len + 8) % 64);
//    if (pad_len == 0) pad_len = 64;
//
//    // 复制缓冲区数据
//    memcpy(final_block, ctx->buffer, ctx->buffer_len);
//
//    // 添加填充位 (1 后跟 0)
//    final_block[ctx->buffer_len] = 0x80;
//
//    // 添加消息长度（以位为单位，64 位整数）
    /*for (i = 0; i < 8; i++) {
        final_block[56 + i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
    }*/
//
//    // 处理最终块
//    SHA256_Transform(ctx, final_block);
//
//    // 输出哈希值
    /*for (i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }*/
//}
//
//// HMAC-SHA256实现
//void hmac_sha256(const uint8* key, size_t key_len,
//    const uint8* message, size_t message_len,
//    uint8* hmac_result) {
//    SHA256_CTX ctx;
//    uint8 key_hash[32];
//    uint8 o_key_pad[64];
//    uint8 i_key_pad[64];
//    int i;
//
//    // 如果密钥长度超过块大小，对密钥进行哈希
//    if (key_len > 64) {
//        SHA256_Init(&ctx);
//        SHA256_Update(&ctx, key, key_len);
//        SHA256_Final(key_hash, &ctx);
//        key = key_hash;
//        key_len = 32;
//    }
//    
//    
//
//    // 初始化内部和外部填充
//    for (i = 0; i < 64; i++) {
//        if (i < key_len) {
//            i_key_pad[i] = key[i] ^ 0x36;  // 内部填充：密钥 XOR 0x36
//            o_key_pad[i] = key[i] ^ 0x5C;  // 外部填充：密钥 XOR 0x5C
//        }
//        else {
//            i_key_pad[i] = 0x36;           // 填充剩余字节为0x36
//            o_key_pad[i] = 0x5C;           // 填充剩余字节为0x5C
//        }
//    }
//
//    // 计算内部哈希：H((K' XOR ipad) || data)
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, i_key_pad, 64);
//    SHA256_Update(&ctx, message, message_len);
//    SHA256_Final(hmac_result, &ctx);
//
//    // 计算外部哈希：H((K' XOR opad) || H((K' XOR ipad) || data))
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, o_key_pad, 64);
//    SHA256_Update(&ctx, hmac_result, 32);
//    SHA256_Final(hmac_result, &ctx);
//}
//
//// 辅助函数：将哈希值转换为十六进制字符串
//void hmac_to_hex_string(const uint8 digest[32], char hex_string[65]) {
    /*static const char hex_chars[16] = "0123456789abcdef";
    int i;

    for (i = 0; i < 32; i++) {
        hex_string[i * 2] = hex_chars[(digest[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[digest[i] & 0xF];
    }
    hex_string[64] = '\0';*/
//}
//
//// 示例使用
//int main() {
//    const char* key = "secret";
//    const char* message = "111";
//    uint8 hmac_result[32];
//    char hex_result[65];
//
//    hmac_sha256((const uint8*)key, strlen(key),
//        (const uint8*)message, strlen(message),
//        hmac_result);
//
//    hmac_to_hex_string(hmac_result, hex_result);
//
//    printf("Key: %s\n", key);
//    printf("Message: %s\n", message);
//    printf("HMAC-SHA256: %s\n", hex_result);
//
//    return 0;
//}

typedef struct{
    uint32 state[8];
    uint64 bitcount;
    uint8 buffer[64];
    int buffer_len;
}sha256_CTX;




void sha256_Init(sha256_CTX* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    
    ctx->bitcount = 0;
    ctx->buffer_len = 0;
}



void sha256_Transform(sha256_CTX* ctx, const uint8 data[64]) {
    uint32 a, b, c, d, e, f, g, h, T1, T2;
    uint32 m[64];
    int i;

        // 将消息块转换为 32 位字
        for (i = 0; i < 16; i++) {
            m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
                (data[i * 4 + 2] << 8) | data[i * 4 + 3];
        }

        // 扩展消息块为 64 个字
        for (i = 16; i < 64; i++) {
            m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
        }

        // 初始化工作变量
        a = ctx->state[0];
        b = ctx->state[1];
        c = ctx->state[2];
        d = ctx->state[3];
        e = ctx->state[4];
        f = ctx->state[5];
        g = ctx->state[6];
        h = ctx->state[7];

        // 64 轮压缩函数
        for (i = 0; i < 64; i++) {
            T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + m[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // 将结果添加到当前哈希值
        ctx->state[0] += a;
        ctx->state[1] += b;
        ctx->state[2] += c;
        ctx->state[3] += d;
        ctx->state[4] += e;
        ctx->state[5] += f;
        ctx->state[6] += g;
        ctx->state[7] += h;

}








void sha256_Update(sha256_CTX* ctx, const uint8* data, size_t len) {

    size_t i, rem;

    ctx->bitcount += len * 8;

    rem = ctx->buffer_len;
    if (rem) {
        size_t copy_len = (len < (64 - rem)) ? len : (64 - rem);
        memcpy(ctx->buffer+rem, data, copy_len);
        ctx->buffer_len += copy_len;

        if (ctx->buffer_len == 64) {
            sha256_Transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
        data += copy_len;
        len -= copy_len;
    }

    //处理剩余数据块
    for (i = 0;i + 64 <= len;i += 64) {
        sha256_Transform(ctx, data + i);
    }

    //将剩余数据块放入缓冲区
    rem = len - i;
    if (rem) {
        memcpy(ctx->buffer, data+i, rem);
        ctx->buffer_len = rem;
    }
    

}



void sha256_Final(sha256_CTX* ctx,  uint8 digest[32]) {
    int i;
    int pad_len;
    uint8 final_block[64] = {0};
    uint64 bit_len = ctx->bitcount;

    //计算填充长度
    pad_len = 64 - ((ctx->buffer_len + 8) % 64);
    if (pad_len == 0) pad_len = 64;
    
    //复制缓冲区数据
    memcpy(final_block, ctx->buffer, ctx->buffer_len);

    //末尾加1
    final_block[ctx->buffer_len] = 0x80;

    //添加消息长度
    for (i = 0; i < 8; i++) {
        final_block[56 + i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
    }

    sha256_Transform(ctx, final_block);

    for (i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}





void hmac_to_hex_string(const uint8 digest[], char hex_string[]) {
    static const char hex_chars[16] = "0123456789abcdef";
    int i;

    for (i = 0; i < 32; i++) {
        hex_string[i * 2] = hex_chars[(digest[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[digest[i] & 0xF];
    }
    hex_string[64] = '\0';
}




void hmac_sha256(const uint8* key, size_t key_len, const uint8* message,
    size_t message_len, uint8* hmac_result) {
    sha256_CTX ctx;
    int i;
    uint8 i_key_pad[64];
    uint8 o_key_pad[64];
    uint8 key_hash[32];


    if (key_len > 64) {
        sha256_Init(&ctx);
        sha256_Update(&ctx, key, key_len);
        sha256_Final(&ctx, key_hash);
        key = key_hash;
        key_len = 32;
    }
    //位模式差异大，汉明距离大，有助于提高扩散性和混淆性
    for (i = 0;i <64;i++){
        if (i < key_len) {
            i_key_pad[i] = key[i] ^ 0x36;
            o_key_pad[i] = key[i] ^ 0x5C;
        }
        else {
            i_key_pad[i] = 0x36;
            o_key_pad[i] = 0x5C;
        }
    }
    
        
 


    sha256_Init(&ctx);
    sha256_Update(&ctx, i_key_pad, 64);
    sha256_Update(&ctx, message, message_len);
    sha256_Final(&ctx, hmac_result);


    sha256_Init(&ctx);
    sha256_Update(&ctx, o_key_pad, 64);
    sha256_Update(&ctx, hmac_result, 32);
    sha256_Final(&ctx, hmac_result);

}







int main() {
    const char* key = "secret";
    const char* message = "123";
    uint8 hmac_result[32];
    char hex_result[65];

    hmac_sha256((const uint8*)key, strlen(key), (const uint8*)message, 
        strlen(message), hmac_result);

    hmac_to_hex_string(hmac_result, hex_result);


    printf("Key: %s\n",key);
    printf("Message:%s\n",message);
    printf("HMAC-SHA256:%s\n",hex_result);


    return 0;
}

















