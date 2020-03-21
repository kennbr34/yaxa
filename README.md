# YAXA
GUI for toy crypto algorithm and file-encryption utility using OpenSSL

# Dependencies
OpenSSL 1.1.*

GTK 3.0

# Compilation

gcc \`pkg-config --cflags gtk+-3.0\` ./yaxafileutil_gui.c -o ./yaxafileutil_gui \`pkg-config --libs gtk+-3.0\` -lcrypto

# Intent and Disclaimer

__*DO NOT RELY ON THIS FOR STRONG ENCRYPTION*__

This program was only written for practice and educational purposes.  It is surely not suitable for secure encryption and I have no professional training as a cryptographer.  I wrote this mostly to learn how to work with 64-bit data values in an application which interests me.

# Details

YAXA stands for Yet Another XOR Algorithm.  Years ago I read a few C tutorials about using the XOR operator for encryption in C. This is colloquially known as "Simple XOR", as coined by Bruce Schneier in Section 1.4 of *"Applied Cryptography"*, and exemplified in dozens of tutorials online.  This has always been known as very insecure for a number of reasons, and over the years I've experimented with ways of trying to make it more secure.  I wandered upon the concept of a "counter-based stream cipher" in Chapter 5 of Jean-Philippe Amausson's *"Serious Cryptography"* and decided to try to implement it.  This is a bit of a step-up from "Simple XOR" and uses the following construction:

*Encryption*

*C₁ = Ctr₁ ⊕ K₁ ⊕ N₁ ⊕ P₁*

*C₂ = Ctr₂ ⊕ K₂ ⊕ N₂ ⊕ P₂*

*...*

*Decryption*

*P₁ = Ctr₁ ⊕ K₁ ⊕ N₁ ⊕ C₁*

*P₂ = Ctr₂ ⊕ K₂ ⊕ N₂ ⊕ C₂*

*...*

Where **'C'** is the cipher-text value, **Ctr** is a counter-variable value, **K** a key value, **N** a nonce value, and **P** a plain-text value.  The **Ctr** value is sequentially incremented with each repetition over the message so that even if the end of **K** or **N** is reached before the end of **P/C**, **Ctr** generates a *keystream* that doesn't repeat (aka non-periodic) so long as the length of the message is within **Ctr**'s range of distinct values. The nonce-value **N** prevents key re-use so that the entire construction generates a keystream that is effectively a one-time-pad even if the same key is used, so long as the nonce is not reused.

I modified my algorithm a little bit to omit the nonce value because I'm using a salt with scrypt to generate a distinct key derived from a password, so the salt will effectively replace the nonce and make it redundant. In addition to this, I'm using a massive 512 kilobyte salt, so it is extremely unlikely to encounter any salt-reuse.  This massive salt is used to generate an even more massive 32 megabyte key. Finally, all values of **C**, **P**, **K** and **Ctr** are 64-bit which means it actually operates on blocks of data rather than single-bytes like a traditional stream cipher.

The massive 32 megabyte key size was chosen after testing the keystream generated with frequency analysis and dieharder statistical testing. To make it comparable to a one-time-pad, it must be non-periodic and indistinguishable from random.  The 64-bit width of the counter variable ensures that the counter will never wrap-around back to 0 until it reaches 2^64 iterations, with each iteration encrypting 64-bits of data. With the 32 megabyte key, the keystream has an equal distribution of ~0.39% per value, of a possible value range of 1-256 per byte.  Beyond that, it also passes all 'dieharder' statistical tests to make the keystream indistinguishable from random. All together this  means the algorithm can generate a 'one-time-pad' for up to 73,784 petabytes of data.  I also included a frequency analysis tool and a period-search tool that I used to confirm these qualities of the keystream.

Because this algorithm is malleable, meaning a change in a value in the cipher-text would result in a directly correlated change in the plain-text result, I decided to make the file-encryption program use it in an AEAD ( Authenticated Encryption with Associated Data) setup. Using Encrypt-then-MAC composition with HMAC-SHA512, and also a keyed hash of the password used, no decryption is performed if the wrong password was entered, or if the cipher-text and associated data (in this case the salt and password hash) does not pass verification.  This mitigates against chosen-ciphertext and oracle attacks.

Even though the keystream passes statistical testing, it's still not a genuine one-time-pad. Scrypt is used to generate a single 64-byte key, and then a loop and HKDF is used to expand those bytes into several more 64-byte chunks (with each iteration based on the previous 64-bytes derived) to fill the 32 megabyte key. As a one-time-pad is required to be *truly* random, which a deterministic PRNG like this can not achieve, comparing this to a one-time-pad isn't meant to conflate it with being "provably unbreakable", and I have no illusions there isn't some weakness I'm not smart enough to realize.

Beyond the algorithm details, I tried to apply a few best-practice guidelines...
* Constant time comparisons for MAC and keyed-hash verification
* Independent keys for MACs and hashes
* 'Dead-store-elimination'-resistant clean-up functions to sanitize buffers of sensitive data

The real fun was learning how to implement this algorithm with 64-bit values as I hadn't done anything like that before. Luckily it wasn't that complicated and the most complicated part was figuring out how to read and write the data to and from files in 8-byte chunks whlie also compensating for when a file's size is in bytes wasn't a multiple of 8, since this meant there would be a remainder of bytes left over that must beat treated individually.

The next step will be to learn how to implement it with all the values being 128-bit.
