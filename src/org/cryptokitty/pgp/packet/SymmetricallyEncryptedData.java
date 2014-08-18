/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * Not a lot here. Just a blob of encrypted data. See RFC 4880,
 * section 5.7
 */
public class SymmetricallyEncryptedData {

	/*
	 * Encrypted data.
	 */
	private byte[] encrypted;

	/**
	 * 
	 */
	public SymmetricallyEncryptedData(InputStream in)
			throws InvalidPacketException {

		try {
			encrypted = new byte[in.available()];
			in.read(encrypted);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
	}

}
