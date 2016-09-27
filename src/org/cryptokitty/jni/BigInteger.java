/**
 * 
 */
package org.cryptokitty.jni;

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
		System.loadLibrary("ckjni");
	}

	/**
	 * Zero and one constants.
	 */
	public static final BigInteger ZERO = new BigInteger(0L);
	public static final BigInteger ONE = new BigInteger(1L);

	/**
	 * The opaque pointer to the underlying C++ object.
	 */
	private long pointer;

	/**
	 * 
	 */
	public BigInteger() {

		pointer = 0;

	}

	/**
	 * Initialize the integer with a long value.
	 */
	public BigInteger(long lValue) {
		
		initialize(lValue);

	}

	/**
	 * 
	 * @return
	 */
	public native int bitLength();

	/**
	 * Initialize the BigInteger with a long value.
	 */
	private native void initialize(long lValue);

	/**
	 * 
	 * @param exp
	 * @param m
	 * @return A BigInteger that is the value of this integer raised to exp mod m.
	 */
	public native BigInteger modPow(BigInteger exp, BigInteger m);

	/**
	 * Generate a high probability random BigInteger of bitsize bits.
	 * Uses a native secure RNG for entropy.
	 * 
	 * @param bitsize
	 * @param rnd
	 * @return
	 */
	public static native BigInteger probablePrime(int bitsize);

	/**
	 * 
	 * @return Decimal string representation of this integer.
	 */
	public native String toString();

}
