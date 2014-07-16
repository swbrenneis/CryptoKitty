/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.digest.HashValue;

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
	public static final byte ITERATED = 0;

	/*
	 * Hash algoritm.
	 */
	protected byte algorithm;

	/*
	 * Passphrase for the hash.
	 */
	protected String passPhrase;

	/**
	 * 
	 */
	protected String2Key(String passPhrase, byte algorithm)
			throws UnsupportedAlgorithmException {
		this.passPhrase = passPhrase;
		switch (algorithm) {
		case HashValue.MD5:
		case HashValue.SHA1:
		case HashValue.RIPEMD160:
		case HashValue.SHA256:
		case HashValue.SHA384:
		case HashValue.SHA512:
		case HashValue.SHA224:
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
