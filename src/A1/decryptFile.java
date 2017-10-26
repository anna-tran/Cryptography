/******************************************************************************
 File: 	        decryptFile.java
 Purpose:       Java decryption program for cryptographic primitives
 Created:	    February 24, 2008
 Revised:
 Author:         Heather Crawford
 Modified:       Anna Tran

 Description:
 This program uses the functions provided by demo.java created by Heather Crawford
 and performs the following cryptographic operations on the input file:
 - computes a SHA-1 hash of the file's contents
 - decrypts input file (a file encrypted with AES-128-CBC and a randomly generated key),
 and outputs it as "decrypted_file"
 - verifies the DSA signature of the message digest (SHA-1 hash which used a randomly
 generated key pair)

 Requires:       java.io.*, java.security.*, javax.crypto.*

 Compilation:    javac decryptFile.java

 Execution: java decryptFile <input file> <seed>

 Notes:
 http://www.aci.net/kalliste/dsa_java.htm

 ******************************************************************************/

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Arrays;

public class decryptFile {
    private static SecretKeySpec sec_key_spec = null;
    private static Cipher sec_cipher = null;


    public static byte[] aes_decrypt(byte[] data_in) throws Exception{
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


    public static byte[] sha1_hash(byte[] input_data) throws Exception{
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

    public static void main(String args[]) throws Exception{
        FileInputStream ciphertext_file = null;
        String seed = "";
        FileOutputStream out_file = new FileOutputStream("decrypted_file");
        byte[] msg_digest = null;
        boolean verify = false;


        try{
            //decrypt file
            ciphertext_file = new FileInputStream(args[0]);
            byte[] ciphtext = new byte[ciphertext_file.available()];
            ciphertext_file.read(ciphtext);

            seed = args[1];

            //key setup - generate 128 bit key
            byte[] hashed_seed =  sha1_hash(seed.getBytes());
            byte[] aes_hashed_seed = Arrays.copyOf(hashed_seed,16);
            sec_key_spec = new SecretKeySpec(aes_hashed_seed, "AES");

            System.out.println("secret key hash code: " + sec_key_spec.hashCode());

            //create the cipher object that uses AES as the algorithm
            sec_cipher = Cipher.getInstance("AES");

            // decrypt message and separate into message + digest
            byte[] decrypted_bytes = aes_decrypt(ciphtext);
            byte[] msg_bytes = new byte[decrypted_bytes.length-20];
            byte[] digest_bytes = new byte[20];

            System.arraycopy(decrypted_bytes,0,msg_bytes,0,msg_bytes.length);
            System.arraycopy(decrypted_bytes,msg_bytes.length,digest_bytes,0,digest_bytes.length);

            out_file.write(msg_bytes);
            out_file.close();

            // verify that digest is the same
            msg_digest = sha1_hash(msg_bytes);
            System.out.println("Message Digest: " + toHexString(msg_digest));

            verify = Arrays.equals(digest_bytes,msg_digest);
            System.out.println("Digest verified? " + verify);


        }
        catch(Exception e){
            System.out.println(e);
        }
        finally{
            if (ciphertext_file != null){
                ciphertext_file.close();
            }
            if(out_file != null){
                out_file.close();
            }
        }
    }
}
