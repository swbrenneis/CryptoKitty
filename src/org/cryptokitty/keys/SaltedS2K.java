/**
 * 
 */
package org.cryptokitty.keys;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * Creates a salted, hashed key. The salt and passphrase are hashed according
 * to the hash algorithm value. The hash result is truncated or concatenated
 * with additional padded hashes to produce the desired key size. See RFC 4880,
 * section 3.7.1.2.
 * 
 */
public class SaltedS2K extends String2Key {

	/*
	 * Hashing salt.
	 */
	private byte[] salt;

	/**
	 * 
	 */
	public SaltedS2K(int algorithm, byte[] salt)
			throws UnsupportedAlgorithmException {
		super(null, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}
	}

	/**
	 * 
	 */
	public SaltedS2K(String passPhrase, int algorithm, byte[] salt)
			throws UnsupportedAlgorithmException {
		super(passPhrase, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey(int)
	 */
	@Override
	public byte[] generateKey(int bitsize) {

		// It probably isn't necessary to UTF-8 encode this, but we
		// will do it for consistency with the RFC.
		Hash digest = null;
		try {
			digest = HashFactory.getDigest(algorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// This will have been taken care of in the constructor,
			// but just in case...
			System.err.println(e.getMessage());
		}
		if (digest == null) {
			return null;
		}

		byte[] pBytes = passPhrase.getBytes(Charset.forName("UTF-8"));
		digest.update(salt);
		digest.update(pBytes);
		return digest.digest();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		byte[] encoded = new byte[10];
		encoded[0] = 1;
		encoded[1] = (byte)algorithm;
		System.arraycopy(salt, 0, encoded, 2, 8);
		return encoded;
	}

}
