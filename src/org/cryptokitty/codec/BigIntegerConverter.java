/**
 * 
 */
package org.cryptokitty.codec;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @author stevebrenneis
 *
 * This ugly mess is used to convert a CryptoKitty BigInteger
 * to a Java BigInteger. CryptoKitty BigIntegers are always
 * positive, so they don't have the sign byte.
 */
public class BigIntegerConverter {

	/**
	 * The encoded BigInteger value. Format depends on how the
	 * object was constructed,
	 */
	private byte[] encoded;

	/**
	 * 
	 */
	public BigIntegerConverter(java.math.BigInteger integer) {

		byte[] raw = integer.toByteArray();
		encoded = Arrays.copyOfRange(raw, 1, raw.length);

	}

	public BigIntegerConverter(org.cryptokitty.jni.BigInteger integer) {

		byte[] raw = integer.getEncoded();
		ByteBuffer buf = ByteBuffer.allocate(raw.length + 1);
		buf.put((byte)0);
		buf.put(raw);
		encoded = buf.array();

	}

	/**
	 * 
	 * @return The encoded integer. This will be in Java format if
	 * the object was constructed with a CryptoKitty integer or
	 * vice versa.
	 */
	byte[] getEncoded() {
		return encoded;
	}

}
