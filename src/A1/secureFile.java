/******************************************************************************
 File: 	        secureFile.java
 Purpose:       Java decryption program for cryptographic primitives
 Created:	    February 24, 2008
 Revised:
 Author:         Heather Crawford
 Modified:       Anna Tran

 Description:
 This program uses the functions provided by demo.java created by Heather Crawford
 and performs the following cryptographic operations on the input file:
 - computes a SHA-1 hash of the file's contents
 - encrypts the file using AES-128-CBC and a randomly generated key, and writes it to
 the output file "encrypted_file"
 - computes a DSA signature on the SHA-1 hash, using a randomly generated
 key pair

 Requires:       java.io.*, java.security.*, javax.crypto.*

 Compilation:    javac secureFile.java

 Execution: java secureFile <input file> <seed>

 Notes:
 http://www.aci.net/kalliste/dsa_java.htm

 ******************************************************************************/

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class secureFile {
    private static SecretKeySpec sec_key_spec = null;
    private static Cipher sec_cipher = null;


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

    public static byte[] aes_encrypt(byte[] data_in) throws Exception{
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


    public static void main(String[] args) throws IOException {
        FileInputStream plaintext_file = null;
        String seed = "";
        FileOutputStream out_file = new FileOutputStream("encrypted_file");
        byte[] msg_digest = null;
        byte[] aes_ciphertext = null;

        try{
            //open files
            plaintext_file = new FileInputStream(args[0]);
            byte[] msg = new byte[plaintext_file.available()];
            plaintext_file.read(msg);
            seed = args[1];

            //encrypt file with AES
            //key setup - generate 128 bit key
            byte[] hashed_seed =  sha1_hash(seed.getBytes());
            byte[] aes_hashed_seed = Arrays.copyOf(hashed_seed,16);
            sec_key_spec = new SecretKeySpec(aes_hashed_seed, "AES");
            System.out.println("secret key hash code: " + sec_key_spec.hashCode());

            //create the cipher object that uses AES as the algorithm
            sec_cipher = Cipher.getInstance("AES");

            //create message digest
            msg_digest = sha1_hash(msg);
            System.out.println("Message Digest: " + toHexString(msg_digest));

            byte[] new_msg = new byte[msg.length + 20];
            System.arraycopy(msg,0,new_msg,0,msg.length);
            System.arraycopy(msg_digest,0,new_msg,msg.length,20);

            //do AES encryption
            aes_ciphertext = aes_encrypt(new_msg);
            out_file.write(aes_ciphertext);
            out_file.close();


        }
        catch(Exception e){
            System.out.println(e);
        }
        finally{
            if (plaintext_file != null){
                plaintext_file.close();
            }
            if(out_file != null){
                out_file.close();
            }
        }
    }
}
