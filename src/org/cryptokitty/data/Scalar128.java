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
	private long[] value;

	/**
	 * Create the scalar object from a long value. 
	 */
	public Scalar128(long value) {
		this.value = new long[2];
		this.value[0] = 0;
		this.value[1] = value;
	}

	/**
	 * Create the scalar object from a BigInteger value. 
	 */
	public Scalar128(BigInteger value) {
		this.value = new long[2];
		this.value[1] = BigInteger.valueOf(0xffffffffffffffffL).and(value).longValue();
		this.value[0] = value.shiftRight(64).longValue();
	}

	/*
	 * Create the scalar object from an encoded byte array.
	 */
	public Scalar128(byte[] value) {
		this.value = byte2longlong(value);
	}

	/*
	 * Convert a big-endian byte array to a 128 bit long.
	 */
	private long[] byte2longlong(byte[] encoded) {
		long[] answer = { 0, 0 };
		for (int i = encoded.length; i >= 0; --i) {
			long temp = answer[1] >> 56;
			answer[1] = (answer[1] << 8) | encoded[i];
			answer[0] = (answer[0] << 8) | temp;
		}
		return answer;
	}

	/*
	 * Get the fixed length 128 bit encoding.
	 */
	public byte[] getEncoded() {
		return longlong2byte(value);
	}

	/*
	 * Get the scalar value.
	 */
	public BigInteger getValue() {
		return new BigInteger(1, longlong2byte(value));
	}

	/*
	 * Convert 128 bit integer to big-endian byte array.
	 */
	private byte[] longlong2byte(long[] x) {
		byte[] answer = new byte[16];
		answer[0] = (byte)((x[0] >> 56) & 0xff);
		answer[1] = (byte)((x[0] >> 48) & 0xff);
		answer[2] = (byte)((x[0] >> 40) & 0xff);
		answer[3] = (byte)((x[0] >> 32) & 0xff);
		answer[4] = (byte)((x[0] >> 24) & 0xff);
		answer[5] = (byte)((x[0] >> 16) & 0xff);
		answer[6] = (byte)((x[0] >> 8) & 0xff);
		answer[7] = (byte)(x[0] & 0xff);
		answer[8] = (byte)((x[1] >> 56) & 0xff);
		answer[9] = (byte)((x[1] >> 48) & 0xff);
		answer[10] = (byte)((x[1] >> 40) & 0xff);
		answer[11] = (byte)((x[1] >> 32) & 0xff);
		answer[12] = (byte)((x[1] >> 24) & 0xff);
		answer[13] = (byte)((x[1] >> 16) & 0xff);
		answer[14] = (byte)((x[1] >> 8) & 0xff);
		answer[15] = (byte)(x[1] & 0xff);
		return answer;
	}

}
