![yaxagif](https://user-images.githubusercontent.com/38168040/77262419-ec8cf400-6c52-11ea-95da-43f35cc80d9a.gif)

###### (Note: Not actual speed, GIF was edited for demonstration sake)

# YAXA
GUI for toy crypto algorithm and file-encryption utility using OpenSSL

# Dependencies
OpenSSL 1.1.*

GTK 3.0

# Compilation

gcc \`pkg-config --cflags gtk+-3.0\` ./yaxafileutil_gui.c -o ./yaxafileutil_gui \`pkg-config --libs gtk+-3.0\` -lcrypto

# Intent and Disclaimer

__*DO NOT RELY ON THIS FOR STRONG ENCRYPTION*__

This is a hobby program, only written for practice and educational purposes.  It is surely not suitable for secure encryption and I have no formal, academic or professional training as a cryptographer.  I wrote this mostly to learn how to work with 128-bit data values in an application which interests me.

# Details

YAXA stands for Yet Another XOR Algorithm.  Years ago I read a few C tutorials about using the XOR operator for encryption in C. This is colloquially known as "Simple XOR", as coined by Bruce Schneier in Section 1.4 of *"Applied Cryptography"*, and exemplified in dozens of tutorials online.  This has always been known as very insecure for a number of reasons, and over the years I've experimented with ways to make it more secure.  I wandered upon the concept of a "counter-based stream cipher" in Chapter 5 of Jean-Philippe Amausson's *"Serious Cryptography"* and decided to try to implement it.  This is a bit of a step-up from "Simple XOR" and uses the following construction:

*Encryption*

*C₁ = Ctr₁ ⊕ K₁ ⊕ N₁ ⊕ P₁*

*C₂ = Ctr₂ ⊕ K₂ ⊕ N₂ ⊕ P₂*

*...*

*Decryption*

*P₁ = Ctr₁ ⊕ K₁ ⊕ N₁ ⊕ C₁*

*P₂ = Ctr₂ ⊕ K₂ ⊕ N₂ ⊕ C₂*

*...*

**Ctr** is an integer value, **K** a key value, **N** a nonce value, and **P** or **C** a plain-text or cipher-text value respectively.  Each subscripted number affixed represents a respective value in a larger buffer. Each sequential value of **P**, **N**, **K** and **Ctr** is XOR'd against each other to compute the encrypted cipher-text value **C**, until the entire plain-text message is encrypted. Decryption is merely the inverse of the process, with the cipher-text value used instead of the plain-text value.

Since the length of message is likely longer than the key, sequentially encrypting each next value until the end of the message is reached would mean having to start back at the beginning of the key periodically.  The key would start to repeat over the run of the message. This creates a periodic, or 'running' key, and is the first fatal flaw in the "Simple XOR" method which makes it very easy to crack.  To counteract that, the **Ctr** integer value is sequentially incremented with each byte of the message that is encrypted, so that even if the end of the key is reached before the message, and the value **K** begins repeating previous values, the always-unique value of **Ctr** suppresses the periodic repetition of the key in the final output.

The other fatal flaw of "Simple XOR" is that even if one used a key as long as the message to avoid it becoming periodic, if that key is reused for multiple messages, the discovery of the key or plain-text secrets is possible.  That is a gross simplificaiton, but in practice it means that avoiding key reuse is absolutely necessary.  The solution to this is called a 'nonce', short for "Number used only once," represented by the vaue **N**.  This enables the reuse of the same key as long as the nonce is never reused.

Combined to the traditional "Simple XOR" method, the nonce and counter variables can be used to generate a 'keystream' from the key values; it is the vaues of this keystream that are then XOR'd against the plain-text to achieve encryption, instead of the key vaues themselves.  In this way, even if a key is shorter than the message and reused, the nonce and counter variables ensure that the keystream generated is always unique and non-periodic, so mitigating the two fatal flaws of the "Simple XOR" method.

The "Simple XOR" method is often touted in naieve tutorials as being the same as a one-time-pad, though it almost never is. The comparison really originates from the caution that for "Simple XOR" to be secure at all, it must be used as a one-time-pad; however the fact that it must be used like a one-time-pad should not be confused with it actually being one.  Even if the "Simple XOR" method were to use a key that was as long as the message to encrypt, and that key was never reused, the final property of a true one-time-pad is that the key must be truly random, which cannot be achieved with a pseudo-random number generator, as is most often done.  Even in the instance that a truly random key is generated, key management becomes the biggest challenge, making it impractical to use, as has always been the problem with one-time-pads.  This algorithm creates a keystream that mimmicks a one-time-pad, but because the keystream is not truly random it is only comparable to a one-time-pad along two of the three criteria.  Still, I endeavored to make the generated keystream as close to indistinguishable from randomness as I could, and think of it as a pseudo-one-time-pad to express thos qualities and caveates more succinctly.

I modified my algorithm a little bit to omit the nonce value because I'm using a salt with scrypt to generate a distinct key derived from a password, so the salt will effectively replace the nonce and make it redundant. In addition to this, I'm using a massive 512 kilobyte salt, so it is extremely unlikely to encounter any salt-reuse.  This massive salt is used to generate an even more massive 32 megabyte key. Finally, all values of **C**, **P**, **K** and **Ctr** are 128-bit which means it actually operates on blocks of data rather than single-bytes like a traditional stream cipher.

The massive 32 megabyte key size was chosen after testing the keystream generated with frequency analysis and dieharder statistical testing to ensure it was indistinguishable from pseudo-randomness.  The 128-bit width of the counter variable ensures that the counter will never wrap-around back to 0 until it reaches 2^128 iterations, with each iteration encrypting 128-bits of data.  With the 32 megabyte key, the keystream has an equal distribution of ~0.39% per value, of a possible value range of 1-256 per byte.  Beyond that, it also passes all 'dieharder' statistical tests. All together this  means the algorithm can generate a pseudo-one-time-pad keystream for a practically-inexhaustable amount of data (1.759218604×10¹³ yobibytes exactly).  I also included a frequency analysis tool and a period-search tool that I used to confirm these qualities of the keystream.

Because this algorithm is malleable, meaning a change in a value in the cipher-text would result in a directly correlated change in the plain-text result, I decided to make the file-encryption program use it in an AEAD ( Authenticated Encryption with Associated Data) setup. Using Encrypt-then-MAC composition with HMAC-SHA512, and also a keyed hash of the password used, no decryption is performed if the wrong password was entered, or if the cipher-text and associated data (in this case the salt and password hash) does not pass verification.  This mitigates against chosen-ciphertext and oracle attacks.

Even though the keystream passes statistical testing, it's still not a genuine one-time-pad. Scrypt is used to generate a single 64-byte key, and then a loop and HKDF is used to expand those bytes into several more 64-byte chunks (with each iteration based on the previous 64-bytes derived) to fill the 32 megabyte key. As a one-time-pad is required to be *truly* random, which a deterministic PRNG like this can not achieve, comparing this to a one-time-pad isn't meant to conflate it with being "provably unbreakable", and I have no illusions there isn't some weakness I'm not smart enough to realize.

Beyond the algorithm details, I tried to apply a few best-practice guidelines...
* Constant time comparisons for MAC and keyed-hash verification
* Independent keys for MACs and hashes
* 'Dead-store-elimination'-resistant clean-up functions to sanitize buffers of sensitive data

From 64-bit version:

> The real fun was learning how to implement this algorithm with 64-bit values as I hadn't done anything like that before. Luckily it wasn't that complicated and the most complicated part was figuring out how to read and write the data to and from files in 8-byte chunks whlie also compensating for when a file's size is in bytes wasn't a multiple of 8, since this meant there would be a remainder of bytes left over that must beat treated individually.
>
> The next step will be to learn how to implement it with all the values being 128-bit.

Accomplishing a 128-bit version was much easier than I expected.  To increase the bitspace of the values operated on by the XOR operation, I simply used GCC's 128-bit extention type **unsigned __int128** instead of the standard **uint64_t**.  All that was required to accomodate this was to change the portions of the code using 8-byte blocks, to use 16-byte blocks instead.  I suppose this makes it less portable than the 64-bit version, but since this is all for fun anyway, that's not much of a concern.

I suppose a greater challenge would be to learn how to increase it to 128-bit in a more-portable way without relying on GCC's extensions.
