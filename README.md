# yaxa
Toy crypto algorithm and file-encryption utility using OpenSSL

# dependencies
OpenSSL 1.1.*

# compilation

gcc ./yaxafileutil.c -o ./yaxafileutil -lcrypto

# details

YAXA stands for Yet Another XOR Algorithm.  Years ago I read a few C tutorials about using the XOR operator for encryption in C. This is colloquially known as "Simple XOR", as coined by Bruce Schneier in Section 1.4 of "Applied Cryptography", and exemplified in dozens of tutorials online.  This has always been known as very insecure for a number of reasons, and over the years I've experimented with ways of trying to make it more secure.  I wandered upon the concept of a "counter-based stream cipher" in Chapter 5 of Jean-Philippe Amausson's "Serious Cryptography" and decided to try to implement it.  This is a bit of a step-up from "Simple XOR" and uses the following construction:

**C = E(P ⊕ N ⊕ KS = f(K ⊕ Ctr = g(Ctr += 1)))**

Where **'C'** is the cipher-text value resultant of the encryption function **'E'**, which XORs a plain-text value **'P'** against a nonce-value **'N'**, and a key-stream value **'KS'** which is generated by function **'f'** that XORs a key-value **'K'** against a counter-value **'Ctr'** generated by function **'g'**.  The counter-value is sequentially incremented for each value of the plain-text message to generate a non-periodic keystream that is the same length of the message, effectively forming a one-time-pad.

I modified my algorithm a little bit to omit the nonce value in the algorithm because I'm using a salt with PBKDF2 to generate distinct keys, so the salt will effectively replace the nonce and make it redundant. In addition to this, I'm using a massive 512 kilobyte salt, so it is extremely unlikely to encounter any nonce-reuse.  This massive salt is used to generate an even more massive 32 megabyte key. Finally, all values of **C**, **P**, **K** and **Ctr** are 64-bit which means it actually operates on blocks of data rather than single-bytes like a traditional stream cipher.

The massive 32 megabyte key size was chosen after testing the keystream generated with frequency analysis and dieharder statistical testing. To make it comparable to a one-time-pad, it must be non-periodic (i.e. the same length of the message without repeating) and indistinguishable from random.  The 64-bit width of the counter variable ensures that the counter will never wrap-around back to 0 until it reaches 2^64 iterations, with each iteration encrypting 64-bits of data. With the 32 megabyte key, the keystream has an equal distribution of ~0.39% per value, of a possible value range of 1-256 per byte.  Beyond that, it also passes all 'dieharder' statistical tests to make the keystream indistinguishable from random. All together this  means the algorithm can generate a 'one-time-pad' for up to 73,784 petabytes of data.  I also included a frequency analysis tool and a period-search tool that I used to confirm these qualities of the keystream.

Because this algorithm is malleable, meaning a change in a value in the cipher-text would result in a directly correlated change in the plain-text result, I decided to make the file-encryption program use it in an AEAD ( Authenticated Encryption with Associated Data) setup. Using Encrypt-then-MAC composition with HMAC-SHA512, and also a tag generated (also with PBKDF2) by the password used, no decryption is performed if the wrong password was entered, or if the cipher-text does not pass verification.  This mitigates against chosen-ciphertext and oracle attacks.

Even though the keystream passes statistical testing, it's still not a genuine one-time-pad. For one thing, PBKDF2 is used to generate a single 64-byte key, and then a loop is used to expand those bytes into several more 64-byte chunks to fill the 32 megabyte key.  It does this by XOR'ing the previous 64-byte chunk generated byte-by-byte against a random value generated by rand().  rand() is seeded with a 64-bit number also derived with PBKDF2 which is also what the counter variable is initialized to.  While rand() is not known to produce cryptographically-secure random values, since the resultant keystream still passes all statistical tests of dieharder, it still seems to be as indistinguishably random as any CSPRNG would be, though probably much more deterministic.  As a one-time-pad is required to be *truly* random which a deterministic PRNG like this can not achieve, calling this a one-time-pad isn't meant to conflate it with being "provably unbreakable", and I have no illusions there isn't some weakness I'm not smart enough to realize.

Beyond the algorithm details, I tried to apply a few best-practice guidelines...
* Constant time comparisons for MAC and tag verification
* Independent keys for MACs and tags
* 'Dead-store-elimination'-resistant clean-up functions to sanitize buffers of sensitive data
