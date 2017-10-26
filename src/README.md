# Secure file transfer
This README file summarizes the implementation of a secure file transfer between a server and one or more clients.
The .java files for the solution are:
* Server.java
    Starts up a server program that will listen on the port specified on the command line. It takes a user provided
    seed for decrypting incoming messages. It listens for input from each connected client on that port until the
    ServerThread for that client closes the connection.
* ServerThread.java
    Starts up a server thread on the server for the newly connected client on the server port. It waits for input
    from the client, specifically a destination file name, the number of bytes of the source file content, and the
    encrypted content of the source file itself.
    It decrypts the encrypted file, verifies the digest which was appended to it with the actual file content, and
    writes the decrypted actual file content to the destination file if the digest is correct. It sends a success
    message back to the client if the previous steps were successful, otherwise it sends a message denoting failure.
    Following that, it closes the socket between the assigned client and server.
* Client.java
    Starts up a client that connects to a server with a given IP and port number. This client prompts for a seed, a
    source file to transfer to the server, and the name of the destination file on the server. Then, it will send an
    AES encrypted version of the source file contents appended with the contents' digest to the server. It waits for
    a reply from the server before exiting.

This problem has been fully solved and there are no known bugs.
Note that in ServerThread.java and Client.java, there are Thread.sleep() functions in place to assure better
synchronization between message transmission between the two.


## Compilation and testing
Compilation and testing should be done on the "linux.cpsc.ucalgary.ca" department server.

To compile these files, run
    javac *.java

To test the files, the server must be started up before the client.
* Server
    1. To start up the server, run
        java Server [port-number]
       To start up the server with debug logging on, run
        java Server [port-number] debug
    2. Enter a seed to be used as a pseudo-random number for decryption

* Client
    1. To start up a new client, run
        java Client [server-ip-address] [port-number]
       To start up a new client with debug logging on, run
        java Client [server-ip-address] [port-number] debug
    2. Enter a seed to be used as a pseudo-random number for encryption
    3. Enter the name of the source file for sending to the server
    4. Enter the name of the destination file for the server to write the source file contents to

The server will print out if the client message digest is correct and will send a result message to the client to print
out to the screen and the client will exit.


To verify that resulting decrypted text on the server was outputted correctly, run either of
    diff [client-source-file-name] [server-destination-file-name]
    cmp [client-source-file-name] [server-destination-file-name]

Any differences indicate that the encrypted/decrypted file was modified in some way over the transmission or was
not encrypted and decrypted properly.

## File transfer protocol

* All protocol messages sent in byte format
* Client to server
    1. Convert seed using PRNG, in this case JCA SHA1 hash, into a 128-bit secret key.
    2. Create the message digest by applying the JCA SHA1 hash on the file contents. The digest is exactly 20
        bytes in length.
    3. Append the message digest to the end of the file contents.
    4. Encrypt the appended file contents with AES encryption which uses the secret key computed in Step 1.
    5. Send to the server in respective order the destination file name, length of the source file in bytes, and
        the source file contents (encrypted and integrity-protected as explainted in Step 4).
    6. Wait for response message from server to print to the screen before closing the socket and exiting.
* Server to client
    1. Convert seed using PRNG, in this case JCA SHA1 hash, into a 128-bit secret key.
    2. Upon receiving the messages from the client, decrypt the file using AES and the secret key in Step 1.
    3. Split the decrypted text into digest bytes (last 20 bytes of the decrypted text) and message bytes (all
        bytes before the digest bytes).
    4. Check the integrity of the file content by recomputing the digest from the message bytes, and
        verifying that it matches the appended digest bytes.
    5. Upon verification of digest, write the file content (message bytes) to the destination file specifed by the
        client.
    6. Send back a response message, which is be followed by the socket to the client closing and the client exit.
* Confidentiality
    Assured by the encryption of the source file contents using a secret key that can only be computed by users who
    know the seed for encryption/decryption. Similarly, only users who know the seed can correctly decrypt the
    encrypted message.
* Data integrity
    Assured by the use of a message digest appended to the original message before encryption with the secret key and
    AES. Once this message and digest combination is decrypted and split into a separate message and digest, the
    server re-computes the digest from the message bytes. This recomputed digest is compared against the digest that
     was sent by the client. Data integrity is preserved if these digests are same.

