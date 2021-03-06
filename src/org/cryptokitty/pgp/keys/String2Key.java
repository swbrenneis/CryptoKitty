/**
 * 
 */
package org.cryptokitty.pgp.keys;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.pgp.PGPConstants;
import org.cryptokitty.pgp.packet.InvalidPacketException;
import org.cryptokitty.xprovider.UnsupportedAlgorithmException;

/**
 * @author Steve Brenneis
 * 
 * This class abstracts the string to key model for generating symmetric
 * encryption keys. See RFC 4880, section 3.7 
 */
public abstract class String2Key {

	/*
	 * S2K constants.
	 */
	public static final byte SIMPLE = 0;
	public static final byte SALTED = 1;
	public static final byte ITERATED = 3;

	/*
	 * Get an S2K specifier from an input stream.
	 */
	public static String2Key getS2K(InputStream in, String passPhrase)
			throws InvalidPacketException, UnsupportedAlgorithmException {
		try {
			int s2kType = in.read();
			switch (s2kType) {
			case SIMPLE:
				return new SimpleS2K(passPhrase, in.read());
			case SALTED:
				{
					int algorithm = in.read();
					byte[] salt = new byte[8];
					in.read(salt);
					return new SaltedS2K(passPhrase, algorithm, salt);
				}
			case ITERATED:
				{
					int algorithm = in.read();
					byte[] salt = new byte[8];
					in.read(salt);
					return new IteratedS2K(passPhrase, algorithm, salt, in.read());
				}
			default:
				throw new InvalidPacketException("Invalid string to key specifier");
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Hash algoritm.
	 */
	protected int algorithm;

	/*
	 * Passphrase for the hash.
	 */
	protected String passPhrase;

	/**
	 * 
	 */
	protected String2Key(String passPhrase, int algorithm)
			throws UnsupportedAlgorithmException {
		this.passPhrase = passPhrase;
		switch (algorithm) {
		case PGPConstants.MD5:
		case PGPConstants.SHA1:
		case PGPConstants.RIPEMD160:
		case PGPConstants.SHA256:
		case PGPConstants.SHA384:
		case PGPConstants.SHA512:
		case PGPConstants.SHA224:
			break;
		default:
			throw new UnsupportedAlgorithmException("Invalid hash algorithm");
		}
		this.algorithm = algorithm;
	}

	/*
	 * Generate the key.
	 */
	public abstract byte[] generateKey(int bitsize);

	/*
	 * Get encoded S2K specifier.
	 */
	public abstract byte[] getEncoded();

}
