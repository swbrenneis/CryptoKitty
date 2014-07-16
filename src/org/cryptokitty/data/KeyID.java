/**
 * 
 */
package org.cryptokitty.data;

import java.math.BigInteger;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a Key ID. See RFC 4880, section 3.3
 */
public class KeyID {

	/*
	 * The ID.
	 */
	private long id;

	/**
	 * Takes a long value id.
	 */
	public KeyID(long id) {
		this.id = id;
	}

	/**
	 * Takes a big endian octet representation. The array must be
	 * 8 bytes long.
	 */
	public KeyID(byte[] octets) throws DataException {

		if (octets.length != 8) {
			throw new DataException("Invlaid key ID format");
		}

		BigInteger bi = new BigInteger(octets);
		id = bi.longValue();

	}

	/*
	 * Get the encoded value.
	 */
	public byte[] getEncoded() {
		byte[] encoded = new byte[8];
		long encode = id;
		for (int i = 7; i >= 0; i--) {
			encoded[i] = (byte)(id & 0xff);
			encode = encode >> 8;
		}
		return encoded;
	}

}
