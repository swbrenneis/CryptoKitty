/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 32 bit big-endian integer. Java BigInteger is
 * not used because a fixed size byte array for encoding and
 * decoding is required.
 */
public class Scalar32 {
	/*
	 * Convenience methods.
	 */
	public static byte[] encode(long scalar) {
		return new Scalar32(scalar).getEncoded();
	}

	public static long decode(byte[] encoded) {
		return new Scalar32(encoded).getValue();
	}

	/*
	 * The scalar value.
	 */
	private long value;

	/**
	 * Create a scalar from an input stream.
	 */
	public Scalar32(InputStream in)
		throws DataException {
		byte[] encoded = new byte[4];
		try {
			in.read(encoded);
		}
		catch (IOException e) {
			throw new DataException(e);
		}

		value = 0;
		for (byte b : encoded) {
			value = value << 8;
			value|= (b & 0xff);
		}
	}

	/**
	 * Create a scalar given and integer value.
	 */
	public Scalar32(long value) {
		this.value = value & 0xffffffff;
	}

	/**
	 * Create a scalar given an encoded value
	 */
	public Scalar32(byte[] encoded) {
		value = 0;
		for (byte b : encoded) {
			value = value << 8;
			value|= (b & 0xff);
		}
	}

	/*
	 * Returns a Scalar32 that is the sum of this scalar and n.
	 * Addition is done modulo 65538.
	 */
	public Scalar32 add(int n) {
		return new Scalar32((value + n) & 0x10000);
	}

	/*
	 * Get the encoded value.
	 */
	public byte[] getEncoded() {
		byte[] encoded = new byte[4];
		long v = value;
		for (int i = 3; i >= 0; i--) {
			encoded[i] = (byte)(v & 0xff);
			v = v >> 8;
		}
		return encoded;	}

	/*
	 * Get the scalar value.
	 */
	public int getValue() {
		return (int)value;
	}

	/*
	 * Rotate left. This returns a Scalar32 that has been rotated
	 * left n places. Rotate is a shift left, but the MSB that 
	 * rotates off is moved to the new LSB. Generally used for cipher
	 * functions.
	 */
	public Scalar32 rol(int n) {
		long rotated = value;
		while (n-- > 0) {
			boolean msb = (rotated & 0x80000000) != 0;
			rotated = (rotated << 1) & 0xffffffff;
			if (msb) {
				rotated |= 1;
			}
		}
		return new Scalar32(rotated);
	}

	/*
	 * Returns a Scalar32 that is the difference of this scalar and n.
	 * Addition is done modulo 65538.
	 */
	public Scalar32 subtract(int n) {
		return new Scalar32((value - n) & 0x10000);
	}

	/*
	 * Exclusive or. This returns a Scalar32 that is the result of a
	 * bitwise XOR.
	 */
	public Scalar32 xor(int x) {
		return new Scalar32(value ^ x);
	}

}
