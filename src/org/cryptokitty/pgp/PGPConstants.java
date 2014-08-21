/**
 * 
 */
package org.cryptokitty.pgp;

/**
 * @author Steve Brenneis
 *
 */
public class PGPConstants {

	/*
	 * Public key algorithms.
	 */
	public static final int RSA = 1;
	public static final int RSA_ENCRYPT = 2;	// Deprecated.
	public static final int RSA_SIGN = 3;	// Deprecated.
	public static final int ELGAMAL = 16;
	public static final int DSA = 17;
	public static final int EC = 18;	// Reserved.
	public static final int ECDSA = 19;	// Reserved.
	public static final int RESERVED = 20;
	public static final int DIFFIE = 21;	// Reserved.

	/*
	 * Symmetric key algorithms.
	 */
	public static final int PLAINTEXT =	0;
	public static final int IDEA = 1;
	public static final int DES_EDE168 = 2;
	public static final int CAST5 = 3;
	public static final int BLOWFISH = 4;
	public static final int AES128 = 7;
	public static final int AES192 = 8;
	public static final int AES256 = 9;
	public static final int TWOFISH = 10;

	/*
	 * Compression constants.
	 */
	public static final int UNCOMPRESSED = 0;
	public static final int ZIP = 1;
	public static final int ZLIB = 2;
	public static final int BZIP2 = 3;

	/*
	 * Hash algorithms.
	 */
	public static final int MD5 = 1;
	public static final int SHA1 = 2;
	public static final int RIPEMD160 = 3;
	public static final int SHA256 = 8;
	public static final int SHA384 = 9;
	public static final int SHA512 = 10;
	public static final int SHA224 = 11;

	/**
	 * 
	 */
	protected PGPConstants() {
		// TODO Auto-generated constructor stub
	}

}
