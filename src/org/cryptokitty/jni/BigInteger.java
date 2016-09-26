/**
 * 
 */
package org.cryptokitty.jni;

import org.cryptokitty.random.SecureRandom;

/**
 * This is a JNI wrapper for the CryptoKitty-C BigInteger class.
 * The performance of the native Java implementation is terrible.
 * 
 * @author stevebrenneis
 *
 */
public class BigInteger {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("cryptokitty");
	}

	/**
	 * Zero and one constants.
	 */
	public static final BigInteger ZERO = new BigInteger(0L);
	public static final BigInteger ONE = new BigInteger(1L);

	/**
	 * The highest order bit position containing a 1.
	 */
	private int length;

	/**
	 * 
	 */
	public BigInteger() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Initialize the integer with a long value.
	 */
	public BigInteger(long lValue) {
		
	}

	/**
	 * 
	 * @return
	 */
	public int bitLength() {

		return length;

	}

	/**
	 * 
	 * @param exp
	 * @param m
	 * @return A BigInteger that is the value of m raised to exp.
	 */
	public native BigInteger modPow(BigInteger exp, BigInteger m);

	/**
	 * Generate a high probability random BigInteger of bitsize bits.
	 * 
	 * @param bitsize
	 * @param rnd
	 * @return
	 */
	public static native BigInteger probablePrime(int bitsize, SecureRandom rnd);

}
