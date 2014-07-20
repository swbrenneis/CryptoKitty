/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.KeyID;

/**
 * @author Steve Brenneis
 *
 * The one pass signature packet.
 */
public class OnePassSignature {

	/*
	 * The signature hash algorithm.
	 */
	private int hashAlgorithm;

	/*
	 * The signature key ID.
	 */
	private KeyID keyID;

	/*
	 * Nested one pass signature packets.
	 */
	private OnePassSignature next;

	/*
	 * The signature public key algorithm.
	 */
	private int pkAlgorithm;

	/*
	 * Signature type. See SignaturePacket class.
	 */
	private int type;

	/*
	 * Version number. Should always be 3.
	 */
	private int version;

	/**
	 * 
	 */
	public OnePassSignature(InputStream in)
		throws InvalidPacketException {

		next = null;

		// TODO Variable validation

		try {
			version = in.read();
			if (version != 3) {
				throw new InvalidPacketException("Invalid version number");
			}
			type = in.read();
			hashAlgorithm = in.read();
			pkAlgorithm = in.read();
			try {
				keyID = new KeyID(in);
			}
			catch (DataException e) {
				throw new InvalidPacketException(e);
			}

			// Mathematicians shouldn't write software specs.
			int more = in.read();
			if (more == 0) {
				next = new OnePassSignature(in);
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

}
