/**
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
        InputStream is = null;
        OutputStream os = null;
        byte[] destination,msg_len_bytes,ciphtext_bytes;
        int msg_length = 0;
        int read_result;

        try {
            is = sock.getInputStream();
            os = new BufferedOutputStream(sock.getOutputStream());
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
                System.out.println(String.format("Client %d: Waiting for destination file name",idnum));
            }

            // read in destination file name bytes
            // sleep once in a while when no input yet
            while (is.available() == 0)
                Thread.sleep(20);
            destination = new byte[is.available()];
            read_result = is.read(destination);
            String destFileName = new String(destination);

            if (debugOn && read_result != -1) {
                System.out.println(String.format("Client %d: Read in destination file name -- %s",idnum, destFileName));
                System.out.println(String.format("Client %d: Waiting for source file length",idnum));
            } else if (read_result == -1) {
                throw new IOException();
            }

            // read in number of source file bytes
            // sleep once in a while when no input yet

            while (is.available() == 0)
                Thread.sleep(20);
            msg_len_bytes = new byte[is.available()];
            read_result = is.read(msg_len_bytes);
            msg_length = msg_len_bytes[0];

            if (debugOn && read_result != -1) {
                System.out.println(String.format("Client %d: Read in source file length -- %d",idnum,msg_length));
                System.out.println(String.format("Client %d: Waiting for source file contents",idnum));
            } else if (read_result == -1) {
                throw new IOException();
            }

            // read in ciphertext
            // sleep once in a while when no input yet

            while (is.available() == 0)
                Thread.sleep(20);
            ciphtext_bytes = new byte[is.available()];
            read_result = is.read(ciphtext_bytes);

            if (debugOn && read_result != -1) {
                System.out.println(String.format("Client %d: Read in source file contents",idnum));
            } else if (read_result == -1) {
                throw new IOException();
            }


            // decrypt ciphertext and verify message digest
            byte[][] msg_and_digest = decryptFileIntoMsgAndDigest(ciphtext_bytes,msg_length);
            int result = verifyDigest(msg_and_digest[0],msg_and_digest[1]);

            // 1 - digest correct
            // otherwise digest incorrect
            if (result == 1) {
                FileOutputStream out_file = new FileOutputStream(destFileName);
                out_file.write(msg_and_digest[0]);
                out_file.close();
                printDecryptionResult(os, is, 1);
            } else {
                System.out.println(String.format("Client %d: Message digest is incorrect.",idnum));
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
     * Prints a result message to the client's screen and closes all streams
     * @param os        OutputStream to socket
     * @param is        InputStream of socket
     * @param result    1 if message decrypted successfully
     *                  otherwise, decryption failed
     */
    private void printDecryptionResult(OutputStream os, InputStream is, int result) {
        String resultMsg = "";
        if (result == 1) {
            resultMsg = String.format("Server: Message was decrypted successfully!");
        } else {
            resultMsg = String.format("Server: Error in receiving/decrypting message!");
        }

        System.out.println(resultMsg);
        try {
            os.write(resultMsg.getBytes());
            os.flush();
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
        byte[] decrypted_bytes = aes_decrypt(ciphtext);
        byte[] msg_bytes = new byte[msg_length];
        byte[] digest_bytes = new byte[20];

        System.arraycopy(decrypted_bytes,0,msg_bytes,0,msg_length);
        System.arraycopy(decrypted_bytes,msg_bytes.length,digest_bytes,0,digest_bytes.length);
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
