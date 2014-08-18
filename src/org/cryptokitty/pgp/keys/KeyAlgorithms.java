/**
 * 
 */
package org.cryptokitty.pgp.keys;

/**
 * @author Steve Brenneis
 *
 * At the moment, this is just a placeholder class to keep key
 * constants.
 */
public class KeyAlgorithms {

	/*
	 * Public key algorithms.
	 */
	public static final int RSA = 1;
	public static final int RSA_ENCRYPT = 2;
	public static final int RSA_SIGN = 3;
	public static final int ELGAMAL = 16;
	public static final int DSA = 17;
	public static final int ELLIPTIC = 18; // Reserved only. Not supported.
	public static final int ECDSA = 19; // Reserved only. Not supported.
	public static final int X9_42 = 21; // Reserved only. Not supported.

	/*
	 * Symmetric key algorithms.
	 */
	public static final int PLAINTEXT = 0;
	public static final int IDEA = 1;
	public static final int TRIPLE_DES = 2;
	public static final int CAST5 = 3;
	public static final int BLOWFISH = 4;
	public static final int AES128 = 7;
	public static final int AES192 = 8;
	public static final int AES256 = 9;
	public static final int TWOFISH = 10;

	/*
	 * Symmetric key algorithm names.
	 */
	public static final String[] SYMMETRIC_NAMES = {
					"PLAINTEXT", "IDEA", "DESede", "CAST5", "Blowfish",
					"", "", "AES", "AES192", "AES256", "Twofish"
													};

	/*
	 * Check for valid key algorithm.
	 */
	public static boolean validKeyAlgorithm(int keyAlgorithm) {
		if (keyAlgorithm > 1 && keyAlgorithm < 5) {
			return true;
		}
		else if (keyAlgorithm > 6 && keyAlgorithm < 11) {
			return true;
		}
		else {
			return false;
		}
	}

	/**
	 * 
	 */
	protected KeyAlgorithms() {
		// Never instantiated.
	}

}
