package A1; /******************************************************************************
 File: 	    demo.java
 Purpose:        Java demo for cryptographic primitives
 Created:	    February 24, 2008
 Revised:
 Author:         Heather Crawford
 Modified:       N/A

 Description:
 This program performs the following cryptographic operations on the input file:
 - computes a SHA-1 hash of the file's contents
 - computes a HMAC-SHA1 hash of the file's contents, using a randomly generated key
 - encrypts the file using AES-128-CBC and a randomly generated key, and writes it to
 <output file>
 - decrypts output file, and prints the results to the screen
 - computes a DSA signature on the SHA-1 hash, using a randomly generated
 key pair
 - verifies the DSA signature

 Requires:       java.io.*, java.security.*, javax.crypto.*

 Compilation:    javac demo.java

 Execution: java demo <input file> <output file>

 Notes:
 http://www.aci.net/kalliste/dsa_java.htm

 ******************************************************************************/

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
//import cryptix.util.core.BI;
//import cryptix.util.core.Hex;
//import cryptix.provider.key.*;
//import cryptix.provider.md.*;

// use "cmp file1 file2" to compare if file bytes are the same

public class demo{
    private static KeyGenerator key_gen = null;
    private static SecretKey sec_key = null;
    private static byte[] raw = null;
    private static SecretKeySpec sec_key_spec = null;
    private static Cipher sec_cipher = null;

    //for DSA
    private static KeyPairGenerator keypairgen = null;
    private static KeyPair keypair = null;
    private static DSAPrivateKey private_key = null;
    private static DSAPublicKey public_key = null;
    private static Signature dsa_sig = null;
    private static SecureRandom secRan = null;
    private static BigInteger big_sig = null;

    public static void main(String args[]) throws Exception{
        FileInputStream in_file = null;
        FileInputStream in_file2 = null;
        FileOutputStream out_file = null;
        byte[] sha_hash = null;
        byte[] hmac_hash = null;
        byte[] aes_ciphertext = null;
        byte[] sig = null;
        String decrypted_str = new String();
        int read_bytes = 0;
        boolean verify = false;

        try{
            //open files
            in_file = new FileInputStream(args[0]);
            out_file = new FileOutputStream(args[1]);

            //read file into a byte array
            byte[] msg = new byte[in_file.available()];
            read_bytes = in_file.read(msg);

            //SHA-1 Hash
            sha_hash = sha1_hash(msg);

            //print out hash in hex
            System.out.println("SHA-1 Hash: " + toHexString(sha_hash));

            //HMAC SHA-1 CBC Hash
            hmac_hash = hmac_sha1(msg);

            //Print out hash in hex
            System.out.println("SHA-1 HMAC: " + toHexString(hmac_hash));

            //encrypt file with AES
            //key setup - generate 128 bit key
            key_gen = KeyGenerator.getInstance("AES");
            key_gen.init(128);
            sec_key = key_gen.generateKey();

            //get key material in raw form
            raw = sec_key.getEncoded();
            sec_key_spec = new SecretKeySpec(raw, "AES");

            //create the cipher object that uses AES as the algorithm
            sec_cipher = Cipher.getInstance("AES");

            //do AES encryption
            aes_ciphertext = aes_encrypt(msg);
            //System.out.println("encrypted file: " + toHexString(aes_ciphertext));
            out_file.write(aes_ciphertext);
            out_file.close();

            //decrypt file
            in_file2 = new FileInputStream(args[1]);
            byte[] ciphtext = new byte[in_file2.available()];
            in_file2.read(ciphtext);

            decrypted_str = aes_decrypt(ciphtext);
            System.out.println("decrypted: " + decrypted_str);

            //sign the SHA-1 hash of the file with DSA
            sig = generateDSASig(sha_hash);
            big_sig = new BigInteger(sig);
            System.out.println("sig in big int form: " + big_sig);

            //verify signature
            verify = verifyDSASig(sig, sha_hash);
            System.out.println("Signature verified? " + verify);
        }
        catch(Exception e){
            System.out.println(e);
        }
        finally{
            if (in_file != null){
                in_file.close();
            }
            if(out_file != null){
                out_file.close();
            }
            if(in_file2 != null){
                in_file2.close();
            }
        }
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

    public static byte[] hmac_sha1(byte[] in_data) throws Exception{
        byte[] result = null;

        try{
            //generate the HMAC key
            KeyGenerator theKey = KeyGenerator.getInstance("HMACSHA1");
            SecretKey secretKey = theKey.generateKey();

            Mac theMac = Mac.getInstance("HMACSHA1");
            theMac.init(secretKey);

            //create the hash
            result = theMac.doFinal(in_data);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return result;
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

    public static String aes_decrypt(byte[] data_in) throws Exception{
        byte[] decrypted = null;
        String dec_str = null;
        try{
            //set cipher to decrypt mode
            sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

            //do decryption
            decrypted = sec_cipher.doFinal(data_in);

            //convert to string
            dec_str = new String(decrypted);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return dec_str;
    }

    public static byte[] generateDSASig(byte[] hash){
        byte[] ret = null;

        try{
            keypairgen = KeyPairGenerator.getInstance("DSA");
            secRan = SecureRandom.getInstance("SHA1PRNG");
            keypairgen.initialize(1024, secRan);
            keypair = keypairgen.generateKeyPair();

            //get private and public keys
            private_key = (DSAPrivateKey) keypair.getPrivate();
            public_key = (DSAPublicKey) keypair.getPublic();

            //make DSA object
            dsa_sig = Signature.getInstance("SHA/DSA");
            dsa_sig.initSign(private_key);
            dsa_sig.update(hash);
            ret = dsa_sig.sign();
        }
        catch(Exception e){
            System.out.println(e);
        }

        return ret;
    }

    public static boolean verifyDSASig(byte[] signature, byte[] hash){
        boolean verified = false;

        try{
            //put signature in Verify mode
            dsa_sig.initVerify(public_key);

            //load the data to verify
            dsa_sig.update(hash);

            //get verification boolean
            verified = dsa_sig.verify(signature);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return verified;
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
