package A3;
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
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Random;


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
     * @param parent Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server parent, int id, boolean debugOn) throws Exception {
        this.parent = parent;
        this.sock = s;
        this.idnum = id;

        this.debugOn = debugOn;
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

            computeSecretKey(is,os);

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
            if (debugOn) {
                System.out.println(String.format("-- Client %d: Destination file hex %s",idnum,CryptoUtilities
                        .toHexString(destination)));
            }
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
     * Computes the secret key between Client and Server.
     *  1. Wait for p and g from server, then find a b such that 0 <= b <= p-2.
     *  2. Send g^a (mod p) to server.
     *  3. Wait for g^b (mod p) from server.
     *  4. Compute key = (g^b)^a (mod p)
     *  5. Passes the key as a byte array createSecKeySpec which generates a keyspec
     * @param is            DataInputStream to client
     * @param os            DataOutputStream from client
     * @throws Exception
     */
    private void computeSecretKey(DataInputStream is, DataOutputStream os) throws Exception {
        BigInteger q, p, g, b, gPowAModP, gPowBModP, key;

        // create public p and g, by first creating a 511 bit q


        q = createQ();

        if (debugOn) {
            System.out.println(String.format("-- Client %d: bit count of q = %d",idnum, q.bitCount()));
            System.out.println(String.format("-- Client %d: q = %s",idnum, CryptoUtilities
                    .toHexString(q.toByteArray())));
        }
        p = computeP(q);

        if (debugOn) {
            System.out.println(String.format("-- Client %d: bit count of p = %d",idnum, p.bitCount()));
            System.out.println(String.format("-- Client %d: p = %s",idnum, CryptoUtilities
                    .toHexString(p.toByteArray())));
        }
        g = createG(p,q);
        if (debugOn) {
            System.out.println(String.format("-- Client %d: g = %s",idnum, CryptoUtilities
                    .toHexString(g.toByteArray())));
        }

        System.out.println(String.format("-- Client %d: Sending p to client",idnum));
        os.write(p.toByteArray());
        os.flush();

        Thread.sleep(100);

        System.out.println(String.format("-- Client %d: Sending g to client",idnum));
        os.write(g.toByteArray());
        os.flush();

        if (debugOn) {
            System.out.println(String.format("-- Client %d: Generating random number b",idnum));
        }
        b = CryptoUtilities.generateSecretNum(p);

        if (debugOn) {
            System.out.println(String.format("-- Client %d: b = %s",idnum, CryptoUtilities
                    .toHexString(b.toByteArray())));
            System.out.println(String.format("-- Client %d: Waiting for g^a (mod p) from client",idnum));
        }
        while(is.available() == 0)
            Thread.sleep(20);
        gPowAModP = new BigInteger(readClientAnswer(is));

        gPowBModP = g.modPow(b,p);
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Hash code of g^a (mod p) is %s",idnum, CryptoUtilities
                    .toHexString(gPowAModP.toByteArray())));
            System.out.println(String.format("-- Client %d: Sending g^b (mod p) to client",idnum));
            System.out.println(String.format("-- Client %d: Hash code of g^b (mod p) is %s",idnum, CryptoUtilities
                    .toHexString(gPowBModP.toByteArray())));
        }
        os.write(gPowBModP.toByteArray());
        os.flush();

        Thread.sleep(100);

        if (debugOn) {
            System.out.println("Computing key = (g^a)^b (mod p)");
        }
        key = gPowAModP.modPow(b,p);

        this.sec_key_spec = CryptoUtilities.createSecKeySpec(key.toByteArray(), debugOn);
    }

    /**
     * Create a primitive root g of p
     * @param p     a large prime
     * @param q     a large prime that generates p
     * @return  primitive root g of p
     */
    private BigInteger createG(BigInteger p, BigInteger q) {
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Creating g", idnum));
        }

        // g = 2 initially
        BigInteger g = new BigInteger("2");
        BigInteger one = new BigInteger("1");

        // BigInteger representation of p - 2
        BigInteger pMinus2 = p.subtract(one).subtract(one);

        BigInteger result;

        // while g <= p-2
        while (g.compareTo(pMinus2) < 1) {
            result = g.modPow(q,p);

            // if g^q (mod p) equivalent to 1
            if (!result.equals(one)) {
                return g;
            }

            g = g.add(one);
        }

        return g;
    }

    /**
     * Creates a large prime q such that p = 2q+1 is prime
     * @return  q
     */
    private BigInteger createQ() {
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Creating q", idnum));
        }
        BigInteger q, p;
        do {
            q = new BigInteger(511, 3, new Random());
            p = computeP(q);
        } while (p.isProbablePrime(3));
        return q;
    }

    /**
     * Computes the value of p = 2q+1 given q
     * @param q a large prime value to generate p
     * @return  p
     */
    private BigInteger computeP(BigInteger q) {
        if (debugOn) {
            System.out.println(String.format("-- Client %d: Computing p", idnum));
        }
        BigInteger two, one, p;
        two = new BigInteger("2");
        one = new BigInteger("1");
        p = q.multiply(two).add(one);

        return p;
    }

    /**
     * Reads an answer from the client
     * @param in    the input stream to get responses from the client
     * @return      the server client as a byte array
     * @throws Exception    if there was a problem reading the client answer
     */
    private byte[] readClientAnswer(InputStream in) throws Exception {
        byte[] clientAnswer = new byte[in.available()];
        if ((in.read(clientAnswer)) == -1) {
            System.out.println("ERROR: Could not read server answer.");
        }
        return clientAnswer;
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
        byte[] msg_digest = CryptoUtilities.sha1_hash(msg_bytes);

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
        byte[] decrypted_bytes = CryptoUtilities.aes_decrypt(ciphtext,this.sec_cipher,this.sec_key_spec);
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

}
