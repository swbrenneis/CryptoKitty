/**
 * 
 */
package org.cryptokitty.codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 16 bit big endian scalar value used
 * for counts and other integer data. Java BigInteger is
 * not used because a fixed size byte array for encoding and
 * decoding is required.
 */
public class Scalar16 {

	/**
	 * Encoded value.
	 */
	private byte[] encoded;

	/**
	 * Short value.
	 */
	private short value;

	/**
	 * Construct with encoded value.
	 */
	public Scalar16(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getShort();

	}

	/**
	 * Construct with short value.
	 */
	public Scalar16(short value) {

		ByteBuffer buf = ByteBuffer.allocate(2);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putShort(value);
		this.encoded = buf.array();

	}

	/**
	 * 
	 * @param encoded
	 */
	public void decode(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getShort();

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
	public short getValue() {

		return value;

	}

	/**
	 * 
	 * @param value
	 */
	public void setValue(short value) {

		ByteBuffer buf = ByteBuffer.allocate(2);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putShort(value);
		this.encoded = buf.array();

	}

}
