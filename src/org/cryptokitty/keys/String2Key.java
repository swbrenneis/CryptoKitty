/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.digest.HashFactory;

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
		case HashFactory.MD5:
		case HashFactory.SHA1:
		case HashFactory.RIPEMD160:
		case HashFactory.SHA256:
		case HashFactory.SHA384:
		case HashFactory.SHA512:
		case HashFactory.SHA224:
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
