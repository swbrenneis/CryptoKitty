/**
 * 
 */
package org.cryptokitty.data;

/**
 * @author Steve Brenneis
 *
 * Encapsulates the 16 bit big endian scalar value used
 * for counts and other integer data.
 */
public class Scalar {

	/*
	 * Convenience methods.
	 */
	public static byte[] encode(int scalar) {
		return new Scalar(scalar).getEncoded();
	}

	public static int decode(byte[] encoded) {
		return new Scalar(encoded).getValue();
	}

	/*
	 * The scalar value.
	 */
	private int value;

	/**
	 * Create a scalar given and integer value.
	 */
	public Scalar(int value) {
		this.value = value;
	}

	/**
	 * Create a scalar given an encoded value
	 */
	public Scalar(byte[] encoded) {
		value = (encoded[0] & 0xff);
		value = value << 8;
		value |= (encoded[1] & 0xff);
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
