/**
 * 
 */
package org.cryptokitty.data;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * 128 bit integer expressed as a 16 byte fixed length big-endian
 * array.
 */
public class Scalar128 {

	/*
	 * Modulus.
	 */
	private static final BigInteger MODULUS;
	
	static {
		byte[] m = new byte[16];
		Arrays.fill(m, (byte)0xff);
		MODULUS = new BigInteger(1, m);
	}

	/*
	 * Convenience methods.
	 */
	public static byte[] encode(long scalar) {
		return new Scalar128(scalar).getEncoded();
	}

	public static byte[] encode(BigInteger scalar) {
		return new Scalar128(scalar).getEncoded();
	}

	public static BigInteger decode(byte[] encoded) {
		return new Scalar128(encoded).getValue();
	}

	/*
	 * The value 
	 */
	private BigInteger value;

	/**
	 * Create the scalar object from a long value. 
	 */
	public Scalar128(long value) {
		this.value = BigInteger.valueOf(value);
	}

	/**
	 * Create the scalar object from a BigInteger value. 
	 */
	public Scalar128(BigInteger value) {
		this.value = new BigInteger(value.toString());
	}

	/*
	 * Create the scalar object from an encoded byte array.
	 */
	public Scalar128(byte[] value) {
		this.value = new BigInteger(value);
	}

	/*
	 * Get the fixed length 128 bit encoding.
	 */
	public byte[] getEncoded() {
		byte[] result = value.toByteArray();
		if (result.length == 16) {
			return result;
		}
		else {
			byte[] finalResult = new byte[16];
			Arrays.fill(finalResult, (byte)0);
			System.arraycopy(result, 0, finalResult, 16 - result.length, result.length);
			return finalResult;
		}
	}

	/*
	 * Get the scalar value.
	 */
	public BigInteger getValue() {
		return new BigInteger(value.toString());
	}

}
