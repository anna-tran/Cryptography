package A3;
/**
 * Structure taken from the CPSC 418 - Fall 2017 website.
 * Modified by: Anna Tran
 * Student ID: 10128425
 * File: Client.java
 *
 * Client program.  Connects to the server and sends files appended with the
 * file message digest, and encrypted using AES to the server.
 */


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;


public class Client
{
    private Socket sock;  //Socket to communicate with.
    private boolean debugOn = false;

    private SecretKeySpec sec_key_spec = null;
    private Cipher sec_cipher = null;

    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     *             arg[2] is an optional "debug" flag
     */
    public static void main (String [] args)
    {
        if (args.length != 2 && args.length != 3) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("hostname is a string identifying your server");
            System.out.println ("port is a positive integer identifying the port to connect to the server");
            return;
        }

        try {
            boolean debugOn = false;
            if (args.length == 3 && args[2].toLowerCase().equals("debug")) {
                debugOn = true;
            } else if (args.length == 3) {
                System.out.println ("Usage: java Client hostname port#");
                return;
            }

            Client c = new Client(args[0], Integer.parseInt(args[1]),debugOn);

        }
        catch (NumberFormatException e) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("Second argument was not a port number");
            return;
        }catch (Exception e) {
            System.out.println(e.getStackTrace());
        }
    }

    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port, boolean debugOn) throws Exception
    {
        this.debugOn = debugOn;
        this.sec_cipher = Cipher.getInstance("AES");

	/* Allows us to get input from the keyboard. */
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        DataOutputStream out;
        DataInputStream in;
        String source, destination;

	/* Try to connect to the specified host on the specified port. */
        try {
            sock = new Socket (InetAddress.getByName(ipaddress), port);
        }
        catch (UnknownHostException e) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("First argument is not a valid hostname");
            return;
        }
        catch (IOException e) {
            System.out.println ("Could not connect to " + ipaddress + ".");
            return;
        }

	/* Status info */
        System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);

        try {
            out = new DataOutputStream(sock.getOutputStream());
            in = new DataInputStream(sock.getInputStream());
        }
        catch (IOException e) {
            System.out.println ("Could not create output stream.");
            return;
        }


	    /* Wait for the user to type stuff. */
        try {

            System.out.println("Starting Diffie-Hellman key exchange.");
            computeSecretKey(in,out);

            if (debugOn) {
                System.out.println(String.format("-- Starting file transfer"));
                System.out.println(String.format("-- Reading in source file name"));
            }
            // get source file
            System.out.println("Enter the source file name: ");
            source = tryReadLine(stdIn);

            System.out.println(String.format("Source file: %s",source));

            if (debugOn) {
                System.out.println("-- Encrypting source file contents, appended with digest");
            }

            byte[] fileBytes = readSourceFile(source);
            byte[] aes_ciphertext = encryptFile(fileBytes);

            if (debugOn) {
                System.out.println("-- Encrypted source file with digest");
                System.out.println("-- Reading in destination file name");
            }

            // get destination file
            System.out.println("Enter the destination file name: ");
            destination = tryReadLine(stdIn);

            if (debugOn) {
                System.out.println(String.format("-- Destination file hex %s",CryptoUtilities
                        .toHexString(destination.getBytes())));
            }
            System.out.println(String.format("Destination file: %s", destination));

            if (debugOn) {
                System.out.println("-- Writing destination file name to server");
                System.out.println("-- Destination file bytes to server");
            }
            out.flush();
            out.write(destination.getBytes());
            out.flush();

            Thread.sleep(100);

            if (debugOn) {
                System.out.println("-- Writing source file size in bytes to server");
            }
            out.writeInt(fileBytes.length);
            out.flush();

            Thread.sleep(100);


            if (debugOn) {
                System.out.println("-- Writing ciphertext file to server.");
            }
            out.write(aes_ciphertext);
            out.flush();

            Thread.sleep(100);

            if (debugOn) {
                System.out.println("-- Waiting for server response");
            }
            // wait for server answer
            while(in.available() == 0)
                Thread.sleep(20);
            printServerAnswer(in);

            System.out.println ("Client exiting.");
            if (debugOn) {
                System.out.println("-- Closing open streams");
            }
            stdIn.close();
            out.close ();
            sock.close();

        } catch (IOException e) {
            System.out.println(e.getMessage());
            return;
        }
    }

    /**
     * Computes the secret key between Client and Server.
     *  1. Wait for p and g from server, then find an a such that 0 <= a <= p-2.
     *  2. Send g^a (mod p) to server.
     *  3. Wait for g^b (mod p) from server.
     *  4. Compute key = (g^b)^a (mod p)
     *  5. Passes the key as a byte array createSecKeySpec which generates a keyspec
     * @param in        DataInputStream to Server
     * @param out       DataOutputStream from Server
     * @throws Exception
     */
    private void computeSecretKey(DataInputStream in, DataOutputStream out) throws Exception {
        // wait for p and g value from server
        BigInteger p, g, a, gPowAModP, gPowBModP, key;

        if (debugOn) {
            System.out.println("-- Waiting for p from server");
        }
        while(in.available() == 0)
            Thread.sleep(50);
        p = new BigInteger(readServerAnswer(in));

        if (debugOn) {
            System.out.println(String.format("-- bit count of p = %d", p.bitCount()));
            System.out.println(String.format("-- p = %s", CryptoUtilities.toHexString(p.toByteArray())));
            System.out.println("-- Waiting for g from server");
        }
        while(in.available() == 0)
            Thread.sleep(50);
        g = new BigInteger(readServerAnswer(in));

        if (debugOn) {
            System.out.println(String.format("-- g = %s", CryptoUtilities.toHexString(g.toByteArray())));
            System.out.println("-- Generating random number a");
        }
        a = CryptoUtilities.generateSecretNum(p);

        gPowAModP = g.modPow(a,p);
        if (debugOn) {
            System.out.println(String.format("-- a = %s", CryptoUtilities.toHexString(a.toByteArray())));
            System.out.println(String.format("-- g^a (mod p) = %s", CryptoUtilities
                    .toHexString(gPowAModP.toByteArray())));
            System.out.println("-- Sending g^a (mod p) to server");
        }
        out.write(gPowAModP.toByteArray());
        out.flush();

        Thread.sleep(100);

        if (debugOn) {
            System.out.println("-- Waiting for g^b (mod p) from server");
        }
        while(in.available() == 0)
            Thread.sleep(20);
        gPowBModP = new BigInteger(readServerAnswer(in));

        if (debugOn) {
            System.out.println(String.format("-- g^b (mod p) = %s", CryptoUtilities
                    .toHexString(gPowBModP.toByteArray())));
            System.out.println("-- Computing key = (g^b)^a (mod p)");
        }
        key = gPowBModP.modPow(a,p);

        this.sec_key_spec = CryptoUtilities.createSecKeySpec(key.toByteArray(),debugOn);

    }


    /**
     * Reads an answer from the server
     * @param in    the input stream to get responses from the server
     * @return      the server answer as a byte array
     * @throws Exception    if there was a problem reading the server answer
     */
    private byte[] readServerAnswer(InputStream in) throws Exception {
        byte[] serverAnswer = new byte[in.available()];
        if ((in.read(serverAnswer)) == -1) {
            System.out.println("ERROR: Could not read server answer.");
        }
        return serverAnswer;
    }



    /**
     * Read response from the server and print it out to standard output
     *
     * @param in            InputStream from the socket
     * @throws Exception
     */
    private void printServerAnswer(InputStream in) throws Exception{
        byte[] serverAnswer = readServerAnswer(in);
        String serverAnsStr = new String(serverAnswer);
        System.out.println(serverAnsStr);
    }


    /**
     * Try to read line from standard input
     * @param stdIn
     * @return              line read from standard input
     * @throws Exception    if cannot read line from standard input
     */
    private String tryReadLine(BufferedReader stdIn) throws Exception{
        String userInput = stdIn.readLine();
        if (userInput == null)
            throw new IOException("ERROR: Could not read user input");
        else
            return userInput;
    }


    /**
     * Create message digest from message content and append it to the message (into new_msg)
     * Then, encrypt new_msg with AES
     *
     * @param msg           message to be encrypted
     * @return              ciphertext created from message and message digest
     * @throws Exception
     */
    private byte[] encryptFile(byte[] msg) throws Exception {
        //create message digest
        byte[] msg_digest = CryptoUtilities.sha1_hash(msg);
        if (debugOn) {
            System.out.println("-- Encrypting message with AES");
            System.out.println("-- Message Digest: " + CryptoUtilities.toHexString(msg_digest));
        }

        byte[] new_msg = new byte[msg.length + 20];
        System.arraycopy(msg,0,new_msg,0,msg.length);
        System.arraycopy(msg_digest,0,new_msg,msg.length,20);

        //do AES encryption
        return CryptoUtilities.aes_encrypt(new_msg, this.sec_cipher, this.sec_key_spec);

    }

    /**
     * Reads in content from source file given by fileName
     * @param fileName      name of file to read from
     * @return              byte array of file contents
     * @throws IOException
     */
    private byte[] readSourceFile(String fileName) throws IOException {
        if (debugOn) {
            System.out.println("-- Reading from source file " + fileName);
        }
        FileInputStream plaintext_file = new FileInputStream(fileName);
        byte[] msg = new byte[plaintext_file.available()];
        plaintext_file.read(msg);
        return msg;
    }



}
