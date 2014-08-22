/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 64 bit unsigned big-endian integer.
 */
public class Scalar64 {

	/*
	 * Convenience methods.
	 */
	public static byte[] encode(long scalar) {
		return new Scalar64(scalar).getEncoded();
	}

	public static long decode(byte[] encoded) {
		return new Scalar64(encoded).getValue();
	}

	/*
	 * The value.
	 */
	private long value;

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

		value = byte2long(encoded);

	}

	/**
	 * Create a scalar given a long value.
	 */
	public Scalar64(long value) {
		this.value = value;
	}

	/**
	 * Create a scalar given an encoded value
	 */
	public Scalar64(byte[] encoded) {
		this.value = byte2long(encoded);
	}

	/*
	 * Returns a Scalar64 that is the sum of this scalar and n.
	 * Addition is done modulo 2**64.
	 */
	public Scalar64 add(long n) {
		BigInteger v = BigInteger.valueOf(value);
		BigInteger sum = v.add(BigInteger.valueOf(n));
		byte[] m = { 1,0,0,0,0,0,0,0,0 };
		BigInteger mod = sum.mod(new BigInteger(m));
		return new Scalar64(mod.longValue());
	}

	/*
	 * Convert a big-endian byte array to an unsigned long.
	 */
	private long byte2long(byte[] encoded) {
		long answer = 0;
		for (int i = 0; i < encoded.length; ++i) {
			answer = (answer << 8) | (encoded[i] & 0xff);
		}
		return answer;
	}

	/*
	 * Get the encoded value. Forces the output to be 64 bits
	 */
	public byte[] getEncoded() {
		return long2byte(value);
	}

	/*
	 * Get the scalar value.
	 */
	public long getValue() {
		return value;
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

	public Scalar64 subtract(long n) {
		BigInteger sub = BigInteger.valueOf(n);
		return new Scalar64(value.subtract(sub).longValue());
	}
	 */
	/*
	 * Exclusive or. This returns a Scalar64 that is the result of a
	 * bitwise XOR.

	public Scalar64 xor(long x) {
		BigInteger xr = value.xor(BigInteger.valueOf(x));
		return new Scalar64(xr.longValue());
	}
	 */

	/*
	 * Convert a long to a big-endian byte array.
	 */
	private byte[] long2byte(long x) {
		byte[] answer = new byte[8];
		answer[0] = (byte)((x >> 56) & 0xff);
		answer[1] = (byte)((x >> 48) & 0xff);
		answer[2] = (byte)((x >> 40) & 0xff);
		answer[3] = (byte)((x >> 32) & 0xff);
		answer[4] = (byte)((x >> 24) & 0xff);
		answer[5] = (byte)((x >> 16) & 0xff);
		answer[6] = (byte)((x >> 8) & 0xff);
		answer[7] = (byte)(x & 0xff);
		return answer;
	}

}
