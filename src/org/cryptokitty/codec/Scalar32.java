/**
 * 
 */
package org.cryptokitty.codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 32 bit big-endian integer. Java BigInteger is
 * not used because a fixed size byte array for encoding and
 * decoding is required.
 */
public class Scalar32 {

	/**
	 * Encoded value.
	 */
	private byte[] encoded;

	/**
	 * Integer value.
	 */
	private int value;

	/**
	 * Construct with encoded value.
	 */
	public Scalar32(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getInt();

	}

	/**
	 * Construct with integer value.
	 */
	public Scalar32(int value) {

		ByteBuffer buf = ByteBuffer.allocate(4);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putInt(value);
		this.encoded = buf.array();

	}

	/**
	 * 
	 * @param encoded
	 */
	public void decode(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getInt();

	}

	/**
	 * 
	 * @return
	 */
	public byte[] getEncoded() {
		
		return encoded;
		
	}

	/**
	 * 
	 * @return
	 */
	public int getValue() {

		return value;

	}

	/**
	 * 
	 * @param value
	 */
	public void setValue(int value) {

		ByteBuffer buf = ByteBuffer.allocate(4);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putInt(value);
		this.encoded = buf.array();

	}

}
