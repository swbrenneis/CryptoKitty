/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author stevebrenneis
 *
 * Encapsulates a 64 bit big-endian integer. Java BigInteger is
 */
public class Scalar64 {

	/*
	 * Modulus.
	 */
	private static final BigInteger MODULUS;
	
	static {
		byte[] m = new byte[8];
		Arrays.fill(m, (byte)0xff);
		MODULUS = new BigInteger(1, m);
	}

	/*
	 * Convenience methods.
	 */
	public static byte[] encode(int scalar) {
		return new Scalar64(scalar).getEncoded();
	}

	public static long decode(byte[] encoded) {
		return new Scalar64(encoded).getValue();
	}

	/*
	 * The value. Kept as a BigInteger to maintain unsigned-ness
	 */
	private BigInteger value;

	/**
	 * Create a scalar from an input stream.
	 */
	public Scalar64(InputStream in)
		throws DataException {

		byte[] encoded = new byte[8];
		try {
			in.read(encoded);
		}
		catch (IOException e) {
			throw new DataException(e);
		}

		value = new BigInteger(1, encoded);

	}

	/**
	 * Create a scalar given a long value.
	 */
	public Scalar64(long value) {
		this.value = BigInteger.valueOf(value);
	}

	/**
	 * Create a scalar given an encoded value
	 */
	public Scalar64(byte[] encoded) {
		this.value = new BigInteger(1, encoded).and(MODULUS);
	}

	/*
	 * Returns a Scalar32 that is the sum of this scalar and n.
	 * Addition is done modulo 2**64.
	 */
	public Scalar64 add(long n) {
		BigInteger sum = value.add(BigInteger.valueOf(n));
		BigInteger mod = sum.and(MODULUS);
		return new Scalar64(mod.longValue());
	}

	/*
	 * Get the encoded value. Forces the output to be 64 bits
	 */
	public byte[] getEncoded() {
		byte[] encoded = new byte[8];
		Arrays.fill(encoded, (byte)(0));
		byte[] v = value.toByteArray();
		System.arraycopy(v, 0, encoded, 8 - v.length, v.length);
		return encoded;
	}

	/*
	 * Get the scalar value.
	 */
	public long getValue() {
		return value.longValue();
	}

	/*
	 * Rotate left. This returns a Scalar32 that has been rotated
	 * left n places. Rotate is a shift left, but the MSB that 
	 * rotates off is moved to the new LSB. Generally used for cipher
	 * functions.
	public Scalar32 rol(int n) {
		int rotated = value;
		while (n-- > 0) {
			boolean msb = (rotated & 0x80000000) != 0;
			rotated = rotated << 1;
			if (msb) {
				rotated |= 1;
			}
		}
		return new Scalar32(rotated);
	}
	 */

	/*
	 * Returns a Scalar64 that is the difference of this scalar and n.
	 */
	public Scalar64 subtract(long n) {
		BigInteger sub = BigInteger.valueOf(n);
		return new Scalar64(value.subtract(sub).longValue());
	}

	/*
	 * Exclusive or. This returns a Scalar64 that is the result of a
	 * bitwise XOR.
	 */
	public Scalar64 xor(long x) {
		BigInteger xr = value.xor(BigInteger.valueOf(x));
		return new Scalar64(xr.longValue());
	}

}
