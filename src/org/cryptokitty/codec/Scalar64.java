/**
 * 
 */
package org.cryptokitty.codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a 64 bit unsigned big-endian integer.
 */
public class Scalar64 {

	/**
	 * Encoded value.
	 */
	private byte[] encoded;

	/**
	 * Long value.
	 */
	private long value;

	/**
	 * Construct with encoded value.
	 */
	public Scalar64(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getLong();

	}

	/**
	 * Construct with integer value.
	 */
	public Scalar64(long value) {

		ByteBuffer buf = ByteBuffer.allocate(8);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putLong(value);
		this.encoded = buf.array();

	}

	/**
	 * 
	 * @param encoded
	 */
	public void decode(byte[] encoded) {

		ByteBuffer buf = ByteBuffer.wrap(encoded);
		buf.order(ByteOrder.BIG_ENDIAN);
		this.value = buf.getLong();

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
	public long getValue() {

		return value;

	}

	/**
	 * 
	 * @param value
	 */
	public void setValue(long value) {

		ByteBuffer buf = ByteBuffer.allocate(8);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putLong(value);
		this.encoded = buf.array();

	}

}
