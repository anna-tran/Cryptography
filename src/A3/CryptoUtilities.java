package A3;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class CryptoUtilities {
    /**
     * Generate a secret number 0 <= a <= p-2
     * @param p a prime number p
     * @return  a
     */
    public static BigInteger generateSecretNum(BigInteger p) {
        BigInteger a = new BigInteger(512,new Random());
        BigInteger two = new BigInteger("2");
        if (a.compareTo(p.subtract(two)) > 0) {
            a = p.subtract(two);
        }
        return a;
    }

    /**
     * Transform the user given key (a byte array) to a secret key specification
     * @param key          key to transform
     * @throws Exception
     */
    public static SecretKeySpec createSecKeySpec(byte[] key, boolean debugOn) throws Exception{

        byte[] hashed_key =  CryptoUtilities.sha1_hash(key);
        byte[] aes_hashed_key = Arrays.copyOf(hashed_key,16);
        SecretKeySpec sec_key_spec = new SecretKeySpec(aes_hashed_key, "AES");
        if (debugOn) {
            System.out.println(String.format("-- Using key %s to encrypt files.",CryptoUtilities.toHexString
                    (aes_hashed_key)));
            System.out.println(String.format("-- Secret key hash code is %d.", sec_key_spec.hashCode()));
        }

        return sec_key_spec;
    }


    /**
     * Encrypts data with AES
     * @param input_data    data to be encrypted
     * @return              encrypted data
     * @throws Exception
     */
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

    /**
     * Encrypts byte data with AES
     * @param data_in       data to encrypt
     * @return              encrypted data
     * @throws Exception
     */
    public static byte[] aes_encrypt(byte[] data_in, Cipher sec_cipher, SecretKeySpec sec_key_spec) throws Exception{
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


    /**
     * Decrypts byte data with AES
     * @param data_in       data to decrypt
     * @return              decrypted data
     * @throws Exception
     */
    public static byte[] aes_decrypt(byte[] data_in, Cipher sec_cipher, SecretKeySpec sec_key_spec) throws Exception{
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
