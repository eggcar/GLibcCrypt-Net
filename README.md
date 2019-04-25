# GLibcCrypt-Net
C# implementation of GLibc crypt() algorithm which can be used for Linux user authentication.

Support MD5/SHA-256/SHA-256 with specified rounds/SHA-512/SHA-512 with specified rounds algorithm.

As most modern linux distributions no longer use DES as default crypt algorithm, DES is not supported for now.

# Usage

Just call Crypt() func and pass password + salt string, you will get the hashed string, which is exactly the same as most linux distribution /etc/shadow file contains.
