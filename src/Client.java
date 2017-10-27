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
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


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

            Client c = new Client (args[0], Integer.parseInt(args[1]),debugOn);

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
        OutputStream out;
        InputStream in;
        String seed, source, destination;

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
            out = new BufferedOutputStream(sock.getOutputStream());
            in = sock.getInputStream();
        }
        catch (IOException e) {
            System.out.println ("Could not create output stream.");
            return;
        }


	    /* Wait for the user to type stuff. */
        try {
            // get seed

            if (debugOn) {
                System.out.println(String.format("-- Getting key (seed) from user"));
            }

            System.out.println("Enter the seed for the encryption: ");
            seed = tryReadLine(stdIn);
            readSeed(seed);


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

            System.out.println(String.format("Destination file: %s", destination));

            if (debugOn) {
                System.out.println("-- Writing destination file name to server");
            }
            out.write(destination.getBytes());
            out.flush();

            Thread.sleep(100);

            if (debugOn) {
                System.out.println("-- Writing source file size in bytes to server");
            }
            out.write((byte)(fileBytes.length));
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
            readServerAnswer(in);

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
     * Read response from the server and print it out to standard output
     *
     * @param in            InputStream from the socket
     * @throws Exception
     */
    private void readServerAnswer(InputStream in) throws Exception{
        byte[] serverAnswer = new byte[in.available()];
        if ((in.read(serverAnswer)) == -1) {
            System.out.println("ERROR: Could not read server answer.");
        } else {
            String serverAnsStr = new String(serverAnswer);
            System.out.println(serverAnsStr);
        }

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
        byte[] msg_digest = sha1_hash(msg);
        if (debugOn) {
            System.out.println("-- Encrypting message with AES");
            System.out.println("-- Message Digest: " + toHexString(msg_digest));
        }


        byte[] new_msg = new byte[msg.length + 20];
        System.arraycopy(msg,0,new_msg,0,msg.length);
        System.arraycopy(msg_digest,0,new_msg,msg.length,20);

        //do AES encryption
        return aes_encrypt(new_msg);

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

    /**
     * Transform the user given seed to a secret key specification
     * @param seed          seed string to transform
     * @throws Exception
     */
    private void readSeed(String seed) throws Exception{

        byte[] hashed_seed =  sha1_hash(seed.getBytes());
        byte[] aes_hashed_seed = Arrays.copyOf(hashed_seed,16);
        this.sec_key_spec = new SecretKeySpec(aes_hashed_seed, "AES");
        if (debugOn) {
            System.out.println(String.format("-- Using seed %s to encrypt files.",toHexString(aes_hashed_seed)));
            System.out.println(String.format("-- Secret key hash code is %d.",this.sec_key_spec.hashCode()));
        }
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

    /**
     * Encrypts byte data with AES
     * @param data_in       data to encrypt
     * @return              encrypted data
     * @throws Exception
     */
    public byte[] aes_encrypt(byte[] data_in) throws Exception{
        byte[] out_bytes = null;
        try{
            //set cipher object to encrypt mode
            sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec);

            //create ciphertext
            out_bytes = sec_cipher.doFinal(data_in);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return out_bytes;
    }

    /*
 * Converts a byte array to hex string
 * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
 */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
}
