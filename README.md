# 🔐 HMAC-SHA256 Implementation in Pure C

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Standard](https://img.shields.io/badge/Compliance-RFC_2104-orange.svg)](https://tools.ietf.org/html/rfc2104)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](#english) | [中文说明](#中文说明)

---

## English

A lightweight, high-performance, and dependency-free implementation of the **HMAC-SHA256** (Keyed-Hash Message Authentication Code) algorithm in pure C. This project includes both the underlying **SHA-256** hash engine and the **HMAC** authentication wrapper, strictly adhering to **RFC 2104** and **FIPS PUB 180-4** standards.

### 🚀 Key Features

* **Zero Dependencies**: Pure standard C implementation. No external cryptography libraries (like OpenSSL) required. Extremely easy to cross-compile for embedded systems/MCUs.
* **Rigorous Security & Buffer Safety**: Prevents memory leaks and buffer overruns. Implements explicit cryptographic padding (`ipad` / `opad`) and ensures clean internal state destruction.
* **Strict RFC 2104 Compliance**: Properly handles cryptographic keys of arbitrary lengths:
  * Keys shorter than the block size (64 bytes) are padded with zeros.
  * Keys longer than the block size are automatically pre-hashed down to 32 bytes before processing.
* **Stream-Ready Design**: Designed with standard `Init`, `Update`, and `Final` modular architectures to support chunk-based streaming of large files or network packets.

### 📦 API Reference

```c
// Initializes the HMAC-SHA256 context with a secret key
void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key, size_t key_len);

// Feeds message data streamingly into the HMAC engine
void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message, size_t message_len);

// Finalizes the calculation and outputs the 32-byte (256-bit) MAC tag
void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac);
