# Variants of AES
AES can be used in various modes of operation, each serving different purposes. Below are some commonly used modes besides GCM:

1. ECB (Electronic Codebook Mode)
   Characteristics: Simple, each block of plaintext is encrypted separately using the same key.
   Security: Not recommended for use due to its weakness. Identical plaintext blocks result in identical ciphertext blocks, making patterns in the data easily discernible.
   Use Cases: Rarely used due to its security flaws.

2. CBC (Cipher Block Chaining)
   Characteristics: Each plaintext block is XORed with the previous ciphertext block before being encrypted. Requires an initialization vector (IV) for the first block.
   Security: More secure than ECB but requires proper management of the IV. Vulnerable to padding oracle attacks if not implemented carefully.
   Use Cases: Often used in file encryption and legacy systems.

3. CTR (Counter Mode)
   Characteristics: Converts a block cipher into a stream cipher. Each block of plaintext is XORed with an encrypted counter. The counter is incremented for each subsequent block.
   Security: Provides parallel encryption/decryption. It is as secure as the underlying block cipher when used with a unique nonce.
   Use Cases: Used in scenarios where parallel encryption/decryption is required.

4. OFB (Output Feedback Mode)
   Characteristics: Converts a block cipher into a stream cipher. The encryption process generates keystream blocks, which are XORed with plaintext blocks to produce ciphertext.
   Security: The same keystream is generated for identical inputs. Secure if the initialization vector (IV) is unique.
   Use Cases: Used in secure communications like secure voice transmission.

5. CFB (Cipher Feedback Mode)
   Characteristics: Converts a block cipher into a stream cipher. Similar to CBC, but allows encryption of data smaller than the block size.
   Security: Secure as long as the IV is unique and properly managed.
   Use Cases: Commonly used for encrypting streams of data.

6. XTS (XEX Tweakable Block Cipher with Ciphertext Stealing)
   Characteristics: Designed for disk encryption. Uses two keys and a "tweak" value to ensure that identical plaintext blocks result in different ciphertext blocks.
   Security: Suitable for encrypting storage devices like hard drives.
   Use Cases: Standard in full disk encryption systems.