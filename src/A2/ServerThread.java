package A2; /**
 * Structure taken from the CPSC 418 - Fall 2017 website.
 * Modified by: Anna Tran
 * Student ID: 10128425
 * File: ServerThread.java
 *
 * Thread to deal with clients who connect to Server. It takes encrypted files from the client,
 * decrypts the message and reports whether confidentiality and integrity have been upheld back
 * to the client.
 */


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.

    private SecretKeySpec sec_key_spec = null;  // key generated from seed for decryption
    private Cipher sec_cipher = null;           // AES cipher
    private boolean debugOn = false;            // debug flag

    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id, SecretKeySpec sec_key_spec, boolean debugOn) throws Exception {
        parent = p;
        sock = s;
        idnum = id;

        this.debugOn = debugOn;
        this.sec_key_spec = sec_key_spec;
        if (debugOn) {
            System.out.println(String.format("Debug Server: Secret key hash code is %d.",this.sec_key_spec.hashCode()));
        }

        //create the cipher object that uses AES as the algorithm
        sec_cipher = Cipher.getInstance("AES");
    }

    /**
     * Getter for id number.
     * @return ID Number
     */
    public int getID ()
    {
        return idnum;
    }

    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
        return sock;
    }

    /**
     * This is what the thread does as it executes.  Listens on the socket
     * for incoming data and then echos it to the screen.  A client can also
     * ask to be disconnected with "exit" or to shutdown the server with "die".
     */
    public void run ()
    {
        DataInputStream is = null;
        DataOutputStream os = null;
        byte[] destination,msg_len_bytes,ciphtext_bytes;
        int msg_length = 0;

        try {
            is = new DataInputStream(sock.getInputStream());
            os = new DataOutputStream(sock.getOutputStream());
        }
        catch (UnknownHostException e) {
            System.out.println ("Unknown host error.");
            return;
        }
        catch (IOException e) {
            System.out.println ("Could not establish communication.");
            return;
        }

	    /* Try to read from the socket */
        try {


            if (debugOn) {
                System.out.println(String.format("-- Client %d: Starting file transfer",idnum));
                System.out.println(String.format("-- Client %d: Waiting for destination file name",idnum));
            }

            // read in destination file name bytes
            // sleep once in a while when no input yet
            while (is.available() == 0)
                Thread.sleep(20);
            destination = new byte[is.available()];
            readIntoBuffer(is,destination);
            String destFileName = new String(destination);

            System.out.println(String.format("Client %d: Output file -- %s", idnum, destFileName));

            if (debugOn) {
                System.out.println(String.format("-- Client %d: Waiting for source file size",idnum));
            }

            // read in number of source file bytes
            // sleep once in a while when no input yet

            while (is.available() == 0)
                Thread.sleep(20);
            msg_length = is.readInt();

            System.out.println(String.format("Client %d: Source file size -- %d",idnum,msg_length));

            if (debugOn) {
                System.out.println(String.format("-- Client %d: Waiting for source file contents",idnum));
            }

            // read in ciphertext
            // sleep once in a while when no input yet

            while (is.available() == 0)
                Thread.sleep(20);
            ciphtext_bytes = new byte[is.available()];
            readIntoBuffer(is,ciphtext_bytes);

            if (debugOn) {
                System.out.println(String.format("-- Client %d: Read in source file contents",idnum));
            }


            // decrypt ciphertext and verify message digest
            byte[][] msg_and_digest = decryptFileIntoMsgAndDigest(ciphtext_bytes,msg_length);
            int result = verifyDigest(msg_and_digest[0],msg_and_digest[1]);

            // 1 - digest correct
            // otherwise digest incorrect
            if (result == 1) {
                if (debugOn) {
                    System.out.println(String.format("-- Client %d: Writing to destination file %s",idnum,destFileName));
                }
                FileOutputStream out_file = new FileOutputStream(destFileName);
                out_file.write(msg_and_digest[0]);
                out_file.close();
                printDecryptionResult(os, is, 1);
            } else {
                printDecryptionResult(os, is, -1);
            }

        }
        catch (IOException e) {
            printDecryptionResult(os, is, -1);
            if (parent.getFlag())
            {
                System.out.println ("shutting down.");
                return;
            }
            return;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            printDecryptionResult(os, is, -1);
            return;
        }

    }

    /**
     * Reads input stream data into the given buffer. If read() is not properly executed, throw an exception.
     * @param is        input stream
     * @param buffer    buffer to read bytes in
     * @return
     * @throws Exception    if input stream cannot read bytes to buffer
     */
    private void readIntoBuffer(DataInputStream is, byte[] buffer) throws Exception{

        int result = is.read(buffer);
        if (result == -1)
            throw new IOException();
    }



    /**
     * Prints a result message to the client's screen and closes all streams
     * @param os        OutputStream to socket
     * @param is        InputStream of socket
     * @param result    1 if message decrypted successfully
     *                  otherwise, decryption failed
     */
    private void printDecryptionResult(OutputStream os, InputStream is, int result) {
        String resultMsg = "";
        if (result == 1) {
            resultMsg = "Message was decrypted successfully!";
        } else {
            resultMsg = "Error in receiving/decrypting message!";
        }

        System.out.println(String.format("Client %d: %s!",idnum,resultMsg));
        try {
            if (debugOn) {
                System.out.println(String.format("Client %d: Writing response to client",idnum));
            }
            os.write(resultMsg.getBytes());
            os.flush();

            if (debugOn) {
                System.out.println(String.format("Client %d: Closing open streams",idnum));
            }
            parent.kill(this);
            is.close();
            sock.close();

        } catch (IOException e) {/*nothing to do*/}
    }

    /**
     * Verify that appended digest is the same as the digest computed from message content
     * @param msg_bytes     message
     * @param digest_bytes  given digest
     * @return              0 if digest incorrect
     *                      1 if digest correct
     * @throws Exception
     */
    public int verifyDigest(byte[] msg_bytes, byte[] digest_bytes) throws Exception {
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Verifying message digest",idnum));
        }
        // verify that digest is the same
        byte[] msg_digest = sha1_hash(msg_bytes);

        boolean verify = Arrays.equals(msg_digest,digest_bytes);
        if (!verify) {
            System.out.println(String.format("Client %d: ERROR -- digest is incorrect.",idnum));
            return 0;
        } else {
            System.out.println(String.format("Client %d: Digest is correct.",idnum));
            return 1;
        }
    }

    /**
     * Decrypts ciphertext by first decrypting with AES, then breaking it up into message
     * and given message digest
     *
     * @param ciphtext      the encrypted text
     * @param msg_length    length of message
     * @return              2-D byte array where
     *                      index 0 is the message
     *                      index 1 is the digest
     * @throws Exception
     */
    public byte[][] decryptFileIntoMsgAndDigest(byte[] ciphtext, int msg_length) throws Exception {
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Decrypting file with AES and seed key",idnum));
        }
        byte[] decrypted_bytes = aes_decrypt(ciphtext);
        byte[] msg_bytes = new byte[decrypted_bytes.length-20];
        byte[] digest_bytes = new byte[20];

        if (debugOn) {
            System.out.println(String.format("-- Client %d: Splitting file contents and MAC",idnum));
            System.out.println(String.format("-- Client %d: Given message length -- %d",idnum,msg_length));
            System.out.println(String.format("-- Client %d: Computed message length -- %d",idnum,msg_bytes.length));
        }


        System.arraycopy(decrypted_bytes,0,msg_bytes,0,msg_length);
        System.arraycopy(decrypted_bytes,msg_length,digest_bytes,0,digest_bytes.length);

        byte[][] msg_and_digest = new byte[2][];
        msg_and_digest[0] = msg_bytes;
        msg_and_digest[1] = digest_bytes;
        return msg_and_digest;
    }

    /**
     * Decrypts byte data with AES
     * @param data_in       data to decrypt
     * @return              decrypted data
     * @throws Exception
     */
    public byte[] aes_decrypt(byte[] data_in) throws Exception{
        byte[] decrypted_bytes = null;
        try{
            //set cipher to decrypt mode
            sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

            //do decryption
            decrypted_bytes = sec_cipher.doFinal(data_in);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return decrypted_bytes;
    }

    /**
     * Encrypts data with AES
     * @param input_data    data to be encrypted
     * @return              encrypted data
     * @throws Exception
     */
    public byte[] sha1_hash(byte[] input_data) throws Exception{
        byte[] hashval = null;
        try{
            //create message digest object
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");

            //make message digest
            hashval = sha1.digest(input_data);
        }
        catch(NoSuchAlgorithmException nsae){
            System.out.println(nsae);
        }
        return hashval;
    }

}
