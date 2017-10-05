/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.pgp.keys.String2Key;
import org.cryptokitty.xprovider.UnsupportedAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * The encrypted session key. Encrypted using a symmetric key.
 * See RFC 4880, section 5.3.
 */
public class SymmetricKeyEncryptedSessionKey {

	/*
	 * The symmetric key.
	 */
	private byte[] key;

	/*
	 * S2K value.
	 */
	@SuppressWarnings("unused")
	private String2Key s2k;

	/*
	 * Symmetric key algorithm.
	 */
	@SuppressWarnings("unused")
	private int skAlgorithm;
	
	/*
	 * Version number. Should be 4.
	 */
	private int version;

	/**
	 * 
	 */
	public SymmetricKeyEncryptedSessionKey(String passPhrase, InputStream in)
			throws InvalidPacketException {

		/*
		 * TODO Check variable validity.
		 */
		try {
			version = in.read();
			if (version != 4) {
				throw new InvalidPacketException("Invalid packet version");
			}
			skAlgorithm = in.read();
			s2k = String2Key.getS2K(in, passPhrase);
			key = null;
			int remaining = in.available();
			if (remaining > 0) {
				key = new byte[remaining];
				in.read(key);
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (UnsupportedAlgorithmException e) {
			throw new InvalidPacketException(e);
		}

	}

}
