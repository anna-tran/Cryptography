# File Encryption and Authentication Implementation
This README file summarizes the implementation of file encryption with message authentication and file decryption with digest verification. Both encryption and decryption take an alphanumeric seed supplemented by the user. The .java files for the solution are:
* secureFile.java
* decryptFile.java

## Secure File
To encrypt a given file, the program does the following:
1. Convert the seed using a PRNG, in this case using the JCA SHA1 hash, into a 128-bit secret key.
2. Create the message digest by appling the JCA SHA1 hash on the file contents. The digest is exactly 20 bytes in length.
3. Append the message digest to the end of the file contents.
4. Encrypt the appended file contents with AES encryption which uses the secret key computer in Step 1.
5. Output the encrypted message to a file in the same directory under the name "encrypted_file".