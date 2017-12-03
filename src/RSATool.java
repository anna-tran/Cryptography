import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */
public class RSATool {
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes
    private final static int N = K-K0-K1;  // message length
    private final static int BITS_IN_A_BYTE = 8;  // number of bits in a byte

    // RSA key data
    private BigInteger n;				// 128 - 16 - 16 = 96 bits
    private BigInteger e, d, p, q;

    // TODO:  add whatever additional variables that are required to implement
    //    Chinese Remainder decryption variables
	private BigInteger dp, dq , px, qy;

    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug)
	    System.out.println("Debug RSA: " + s);
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);

	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }

    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
	 * p and q are Sophie Germain strong primes
	 * px and qy are precomputed, potentially multiple times since BigInteger may not generate correct values for
	 * px and qy for certain values of p and q
	 * Generates dp and dq for Chinese Remainder decryption
	 *
     */
    public RSATool(boolean setDebug) {
		// set the debug flag
		debug = setDebug;

		rnd = new SecureRandom();

		// generate two primes p and q, and precompute px and qy
		do {
			p = createSophieGermainPrime(rnd);
			q = createSophieGermainPrime(rnd);
			BigInteger[] pxAndqy = computePxQy();
			px = pxAndqy[0];
			qy = pxAndqy[1];
		} while (intsTooClose(p,q) || !(px.add(qy).compareTo(BigInteger.ONE) == 0));
		debug("px + qy = " + px.add(qy).toString());

		n = p.multiply(q);

		BigInteger phiN = getPhiOfN(p,q);
		e = selectRandomE(phiN);
		d = e.modInverse(phiN);

		// dp and dq for Chinese Remainder decryption
		dp = d.mod(p.subtract(BigInteger.ONE));
		dq = d.mod(q.subtract(BigInteger.ONE));
	}


	/**
	 * Construct instance for encryption, with n and e supplied as parameters.  No
	 * key generation is performed - assuming that only a public key is loaded
	 * for encryption.
	 */
	public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
		// set the debug flag
		debug = setDebug;

		// initialize random number generator
		rnd = new SecureRandom();

		n = new_n;
		e = new_e;

		d = p = q = null;

	}


	/**
	 * Checks if two BigIntegers are too close (i.e. |p-q| <= 2^128)
	 * @param p		first BigInteger
	 * @param q		second BigInteger
	 * @return true if p and q are too close, false otherwise
	 */
	private boolean intsTooClose(BigInteger p, BigInteger q) {
		BigInteger twoPow128 = (new BigInteger("2")).pow(128);
		if ((p.subtract(q)).abs().compareTo(twoPow128) < 1) {
			debug("p and q too close!");
			return true;
		}
		return false;
	}

	/**
	 * Computes px and qy.
	 * Using the Extended Euclidean Algorithm, finds values x and y that satisfy px + qy = 1 given p and q.
	 * @return a BigInteger array indexed with px, then qy
	 */
	private BigInteger[] computePxQy() {
		ArrayList<BigInteger> quotients = new ArrayList<>();

		// a 	larger of p and q
		// b	smaller of p and q
		BigInteger a,b;
		BigInteger copyP = new BigInteger(1,p.toByteArray());
		BigInteger copyQ = new BigInteger(1,q.toByteArray());
		a = copyP.max(copyQ);
		b = copyP.min(copyQ);

		debug("computing px and qy");

		// create quotient list
		// there are n+1 quotients because we count 0 to n inclusive
		BigInteger quotient, remainder;
		int index = 0;
		do {
			quotient = a.divide(b);
			quotients.add(index, quotient);
			remainder = a.mod(b);

			a = b;
			b = remainder;
			index++;
		} while (remainder.compareTo(BigInteger.ZERO) != 0);

		ArrayList<BigInteger> A = new ArrayList<>();
		ArrayList<BigInteger> B = new ArrayList<>();
		// initialize A[-2] = 0, A[-1] = 1, B[-2] = 1, B[-1] = 0
		// in the first two entries of A and B
		// access into A and B is done at index i+2
		A.add(0, BigInteger.ZERO);
		A.add(1, BigInteger.ONE);
		B.add(0, BigInteger.ONE);
		B.add(1, BigInteger.ZERO);

		// create A and B caches
		int nQuot = quotients.size();
		for (int i = 0; i < nQuot; i++) {
			int abIndex = i + 2;
			BigInteger ak = quotients.get(i).multiply(A.get(abIndex - 1)).add(A.get(abIndex - 2));
			A.add(abIndex, ak);

			BigInteger bk = quotients.get(i).multiply(B.get(abIndex - 1)).add(B.get(abIndex - 2));
			B.add(abIndex, bk);
		}

		// compute x and y
		BigInteger neg1 = BigInteger.ONE.negate();
		BigInteger x = neg1.pow(nQuot - 2).multiply(B.get(nQuot - 2 + 2));
		BigInteger y = neg1.pow(nQuot - 1).multiply(A.get(nQuot - 2 + 2));

		// compute px and qy
		BigInteger[] pxAndqy = new BigInteger[2];
		pxAndqy[0] = p.multiply(x);
		pxAndqy[1] = q.multiply(y);

		return pxAndqy;
	}


	/**
	 * Generates a BigInteger e such that gcd(e,phi(n)) = 1
	 * Intially e starts at 3 and increments by 2 if gcd(e,phi(n)) != 1 until gcd(e,phi(n)) = 1
	 * @param phiN		phi(n) = (p-1)(q-1)
	 * @return	e
	 */
	private BigInteger selectRandomE(BigInteger phiN) {
    	BigInteger e = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		BigInteger gcd;

    	do {
    		e = e.add(two);
    		gcd = phiN.gcd(e);
		} while (gcd.compareTo(BigInteger.ONE) != 0);

		return e;
	}


	/**
	 * Computes phi(n) = (p-1)(q-1)
	 * @param p		first BigInteger
	 * @param q		second BigInteger
	 * @return	phi(n) = (p-1)(q-1)
	 */
	public static BigInteger getPhiOfN(BigInteger p, BigInteger q) {
		BigInteger pMinus1 = p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = q.subtract(BigInteger.ONE);

    	return pMinus1.multiply(qMinus1);
	}


	/**
	 * Creates a Sophie Germain prime b that is 512 bits large with a certainty of 3
	 * i.e. creates a large prime a and returns b = 2a+1
	 * @return  b
	 */
	private BigInteger createSophieGermainPrime(SecureRandom rnd) {
		BigInteger a,b;
		do {
			do {
				a = new BigInteger(511, 3, rnd);
			} while (!a.isProbablePrime(3));

			b = compute2APlus1(a);
		} while (!b.isProbablePrime(3));
		return b;
	}

	/**
	 * Computes the value of b = 2a+1 given a
	 * @param a a large prime value to generate b
	 * @return  b
	 */
	private BigInteger compute2APlus1(BigInteger a) {
		BigInteger two, one, b;
		two = new BigInteger("2");
		one = new BigInteger("1");
		b = a.multiply(two).add(one);

		return b;
	}

	/**
	 * Get n
	 * @return n
	 */
    public BigInteger get_n() {
	return n;
    }

	/**
	 * Get e
	 * @return e
	 */
	public BigInteger get_e() {
	return e;
    }



    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
	debug("In RSA encrypt");

	// make sure plaintext fits into one block
	if (plaintext.length > K-K0-K1)
	    throw new IllegalArgumentException("plaintext longer than one block");

		BigInteger M = new BigInteger(1,plaintext);
		BigInteger newM = encryptOAEP(plaintext);

		BigInteger C = newM.modPow(e,n);
		debug("newM as BigInt = " + CryptoUtilities.toHexString(newM.toByteArray()));

		return removeSignedByte(C.toByteArray(),K);
    }

	/**
	 * Encrypts a plaintext message using RSA-OAEP
	 * @param plaintext		message to encrypt
	 * @return the encrypted plaintext message newM
	 */
	private BigInteger encryptOAEP(byte[] plaintext) {
    	BigInteger newM;

		// initialize 0^k1
		byte[] k1Zeros = new byte[K1];
		Arrays.fill(k1Zeros,(byte) 0);

		do {
			// generate random K0-bit number r
			BigInteger r = new BigInteger(K0*BITS_IN_A_BYTE, rnd);
			byte[] rByteArr = removeSignedByte(r.toByteArray(),K0);

			// M || 0^k1
			byte[] sByteArr = new byte[N+K1];
			System.arraycopy(plaintext, 0, sByteArr, 0, plaintext.length);
			Arrays.fill(sByteArr,plaintext.length,N,(byte)0);
			System.arraycopy(k1Zeros, 0, sByteArr, N, K1);
			debug("size of s = " + sByteArr.length);
			debug("s = " + CryptoUtilities.toHexString(sByteArr));


			// (M || 0^k1) XOR G(r)
			byte[] GofRByteArr = G(rByteArr);
			XORByteArrays(sByteArr,GofRByteArr);

			// r XOR H(s)
			byte[] tByteArr = rByteArr;
			byte[] HofSByteArr = H(sByteArr);
			debug("size of t = " + tByteArr.length);
			debug("t = " + CryptoUtilities.toHexString(tByteArr));
			XORByteArrays(tByteArr,HofSByteArr);

			// new message = s||t
			byte[] newMArr = new byte[K];
			System.arraycopy(sByteArr, 0, newMArr, 0, K-K0);
			System.arraycopy(tByteArr, 0, newMArr, K-K0, K0);
			debug("size of newM first time = " + newMArr.length);
			debug("newM = " + CryptoUtilities.toHexString(newMArr));

			newM = new BigInteger(1, newMArr);
		} while (newM.compareTo(n) >= 0);

		return newM;
	}



    /**
     * Decrypts the given byte array using RSA-OAEP and Chinese Remainder decryption.
     *
     * TODO:  implement RSA-OAEP decryption using the Chinese Remainder method described in Problem 2
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) throws IllegalStateException {
	debug("In RSA decrypt");

	// make sure class is initialized for decryption
	if (d == null)
	    throw new IllegalStateException("RSA class not initialized for decryption");

	// TODO:  implement RSA-OAEP encryption here (replace following return statement)
		BigInteger C = new BigInteger(1,ciphertext);
		debug("C before CRT = " + CryptoUtilities.toHexString(C.toByteArray()));


		// Chinese Remainder decryption
		BigInteger Mp = C.modPow(dp,p);
		BigInteger Mq = C.modPow(dq,q);

		BigInteger newM = (px.multiply(Mq)).add((qy.multiply(Mp))).mod(n);
		byte[] newMByteArr = removeSignedByte(newM.toByteArray(),K);
		debug(String.format("newM has %d bits", newMByteArr.length));
		debug("newM after CRT = " + CryptoUtilities.toHexString(newMByteArr));


		// OAEP decryption
		byte[] mByteArr = decryptOAEP(newMByteArr);
		return mByteArr;
    }


	/**
	 * Decrypts an encrypted message C = (s||t) using RSA-OAEP.
	 * Checks if s has the correct redundancy:
	 * 		if true, return the N-bit message M contained in s
	 * 		else, throw an error stating there is an incorrect redundancy
	 *
	 * @param newMByteArr	the encrypted message C = (s||t)
	 * @return the decrypted plaintext message M
	 * @throws IllegalStateException
	 */
	private byte[] decryptOAEP(byte[] newMByteArr) throws IllegalStateException {
		debug(String.format("newM has %d bits", newMByteArr.length));

		// initialize s and t byte arrays
		byte[] sByteArr = new byte[K-K0];
		byte[] tByteArr = new byte[K0];

		System.arraycopy(newMByteArr, 0,sByteArr,0,K-K0);
		System.arraycopy(newMByteArr,K-K0,tByteArr,0,K0);

		// u = t XOR H(s)
		byte[] uByteArr = tByteArr;
		byte[] HOfSByteArr = H(sByteArr);
		XORByteArrays(uByteArr,HOfSByteArr);
		debug("size of u = " + uByteArr.length);
		debug("u = " + CryptoUtilities.toHexString(uByteArr));


		// v = s XOR G(u)
		byte[] vByteArr = sByteArr;
		byte[] GOfUByteArr = G(uByteArr);
		XORByteArrays(vByteArr,GOfUByteArr);
		debug("size of v = " + vByteArr.length);
		debug("v = " + CryptoUtilities.toHexString(vByteArr));

		// check if redundancy is present
		// throw error if redundancy is incorrect
		boolean hasRedundancy = true;
		for (int i = vByteArr.length-K1; i < vByteArr.length && hasRedundancy; i++) {
			if (vByteArr[i] != ((byte) 0))
				hasRedundancy = false;
		}
		if (!hasRedundancy) {
			throw new IllegalStateException("The plaintext does not have the required redundancy");
		}

		byte[] MByteArr = new byte[N];
		System.arraycopy(vByteArr,0,MByteArr,0,N);
		return MByteArr;
	}


	/**
	 * XOR byte array 1 with byte array 2
	 * @param arr1	array to be XORed
	 * @param arr2	array to XOR with
	 */
    private void XORByteArrays(byte[] arr1, byte[] arr2) {
		for (int i = 0; i < arr1.length && i < arr2.length; i++) {
			arr1[i] ^= arr2[i];
		}

	}

	/**
	 * If BigInteger generates a byte array which contains the signed byte (whether it is signed or not)
	 * truncate the byte array to the desired size
	 * @param num		the number as a byte array
	 * @param numSize	desired byte array size
	 * @return the truncated byte array
	 */
	private byte[] removeSignedByte(byte[] num, int numSize) {
    	byte[] truncatedNum = new byte[numSize];
    	System.arraycopy(num,num.length-numSize,truncatedNum,0,numSize);
    	return truncatedNum;

	}

}
