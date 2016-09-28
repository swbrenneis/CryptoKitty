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
	 * Initialize the integer with a byte array.
	 */
	public BigInteger(byte[] bytes) {

		initialize(bytes);

	}

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of this integer added to other.
	 */
	public native BigInteger add(BigInteger other);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of a bitwise and of this integer
	 * and other.
	 */
	public native BigInteger and(BigInteger other);

	/**
	 * 
	 * @return The number of significant bits in this integer.
	 */
	public native int bitLength();

	/**
	 * 
	 * @return The value of this integer as a byte. May be rounded or truncated.
	 */
	public native byte byteValue();

	/**
	 * 
	 * @param other
	 * @return Returns -1, 0, or 1 when this integer is less than, equal to,
	 * or greater than other, respectively.
	 */
	public native int compareTo(BigInteger other);

	/**
	 * 
	 * @param other
	 * @return 
	 */
	public static native BigInteger copy(BigInteger other);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of the greatest common
	 * denominator of this integer and other.
	 */
	public native BigInteger gcd(BigInteger other);

	/**
	 * 
	 * @return This BigInteger encoded into a byte array.
	 */
	public native byte[] getEncoded();

	/**
	 * Initialize the BigInteger with a long value.
	 * 
	 * @param lValue
	 */
	private native void initialize(long lValue);

	/**
	 * Initialize the BigInteger with a byte array.
	 * 
	 * @param bytes
	 */
	private native void initialize(byte[] bytes);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of this integer modulus other.
	 */
	public native BigInteger mod(BigInteger other);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of the modular inverse of this and
	 * other.
	 */
	public native BigInteger modInverse(BigInteger other);

	/**
	 * 
	 * @param exp
	 * @param m
	 * @return A BigInteger that is the value of this integer raised to exp mod m.
	 */
	public native BigInteger modPow(BigInteger exp, BigInteger m);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of this integer multiplied by other.
	 */
	public native BigInteger multiply(BigInteger other);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of a bitwise or of this integer
	 * and other.
	 */
	public native BigInteger or(BigInteger other);

	/**
	 * 
	 * @param exp
	 * @return A BigInteger that is the value of this integer raised to exp.
	 */
	public native BigInteger pow(long exp);

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
	 * @param count
	 * @return A BigInteger that is the value of this integer bitwise shifted
	 * left count bits.
	 */
	public native BigInteger shiftLeft(long count);

	/**
	 * 
	 * @param count
	 * @return A BigInteger that is the value of this integer bitwise shifted
	 * right count bits.
	 */
	public native BigInteger shiftRight(long count);

	/**
	 * 
	 * @param other
	 * @return A BigInteger that is the value of other subtracted from this
	 * integer.
	 */
	public native BigInteger subtract(BigInteger other);

	/**
	 * 
	 * @return Decimal string representation of this integer.
	 */
	public native String toString();

}
