# CSPC 418 Assignment 1 Problem 6
## File Encryption and Authentication Implementation
This README file summarizes the implementation of file encryption with message authentication and file decryption with digest verification. Both encryption and decryption take an alphanumeric seed supplemented by the user. The .java files for the solution are:
* secureFile.java
* decryptFile.java
The problem is fully solved using these files, which were tested successfully on the University of Calgary’s Linux server at linux.cpsc.ucalgary.ca.


## Secure File
To encrypt a given file, the program does the following:
1. Convert the seed using a PRNG, in this case using the JCA SHA1 hash, into a 128-bit secret key.
2. Create the message digest by applying the JCA SHA1 hash on the file contents. The digest is exactly 20 bytes in length.
3. Append the message digest to the end of the file contents.
4. Encrypt the appended file contents with AES encryption which uses the secret key computed in Step 1.
5. Output the encrypted message to a file in the same directory under the name "encrypted_file"

The computation of the digest is used as the message authentication algorithm.
This program also prints out the hash code of the secret key and the message digest in hexadecimal form.

## Decrypt File
To decrypt the file, the program reads in the contents of a file named "encrypted_file" and does the following:
1. Convert the seed using a PRNG, in this case using the JCA SHA1 hash, into a 128-bit secret key.
2. Decrypt the ciphertext from "encrypted_file" using AES with the secret key in Step 1.
3. Split the decrypted text into digest bytes (last 20 bytes of the decrypted text) and message bytes (all bytes before the digest bytes).
4. Output the message bytes to a file in the same directory under the name "decrypted_file".
5. Verify that the message has not been modified by recomputing the digest from the message bytes and comparing that to the digest bytes in Step 3. The program outputs "Digest verified? " followed by "true" if both digests are the same and "false" otherwise.

This program also prints out the hash code of the secret key and the message digest in hexadecimal form.

## Compilation
To compile these files, run
    javac *.java

To test the files,
1. Encrypt the plaintext file with a user-supplemented seed like so
    java secureFile [plaintext-filename] [seed]
2. Decrypt the resulting ciphertext file with the same seed in Step 1 like so
    java decryptFile encrypted_file [seed]

   The program output will state whether the original message was modified in the encryption-decryption process.
3. To verify that resulting decrypted text was outputted correctly, run either of
    diff [plaintext-filename] decrypted_file
    cmp [plaintext-filename] decrypted_file

   Any differences indicate that the encrypted/decrypted message was modified in some way or was not encrypted and decrypted properly.


