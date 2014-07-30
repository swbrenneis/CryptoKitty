/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 16 bit big endian scalar value used
 * for counts and other integer data. Java BigInteger is
 * not used because a fixed size byte array for encoding and
 * decoding is required.
 */
public class Scalar16 {

	/*
	 * Convenience methods.
	 */
	public static byte[] encode(int scalar) {
		return new Scalar16(scalar).getEncoded();
	}

	public static int decode(byte[] encoded) {
		return new Scalar16(encoded).getValue();
	}

	/*
	 * The scalar value.
	 */
	private int value;

	/**
	 * Create a scalar from an input stream.
	 */
	public Scalar16(InputStream in)
		throws DataException {
		byte[] sBytes = new byte[2];
		try {
			in.read(sBytes);
		}
		catch (IOException e) {
			throw new DataException(e);
		}

		value = (sBytes[0] & 0xff);
		value = value << 8;
		value |= (sBytes[1] & 0xff);		
	}

	/**
	 * Create a scalar given and integer value.
	 */
	public Scalar16(int value) {
		this.value = value & 0xffff;
	}

	/**
	 * Create a scalar given an encoded value
	 */
	public Scalar16(byte[] encoded) {
		value = (encoded[0] & 0xff);
		value = value << 8;
		value |= (encoded[1] & 0xff);
	}

	/*
	 * returns a Scalar16 object that is the sum of addend and
	 * this scalar.
	 */
	public Scalar16 add(Scalar16 addend) {
		int sum = (value + addend.value) % 65536;
		return new Scalar16(sum);
	}

	/*
	 * returns a Scalar16 object that is the sum of addend and
	 * this scalar.
	 */
	public Scalar16 add(int addend) {
		int sum = (value + addend) % 65536;
		return new Scalar16(sum);
	}

	/*
	 * Checks equality of a scalar to this scalar. Proper class
	 * cast is up to the caller.
	 */
	@Override
	public boolean equals(Object other) {
		return value == ((Scalar16)other).value;
	}

	/*
	 * Get the encoded value.
	 */
	public byte[] getEncoded() {
		byte[] encoded = new byte[2];
		int encode = value;
		encoded[1] = (byte)(encode & 0xff);
		encode = encode >> 8;
		encoded[0] = (byte)(encode & 0xff);
		return encoded;
	}

	/*
	 * Get the scalar value.
	 */
	public int getValue() {
		return value;
	}

}
