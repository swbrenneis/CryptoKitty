/**
 * 
 */
package org.cryptokitty.keys;

import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * @author Steve Brenneis
 *
 * Encapsulates a string-to-key method symmetric key.
 * See RFC 4880 for details.
 */
@SuppressWarnings("serial")
public class S2KSecretKey implements SecretKey {

	/*
	 * The algorithm number. See org.cryptokitty.keys. KeyAlgorithms
	 * for details.
	 */
	private int algorithm;

	/*
	 * Raw key material.
	 */
	private byte[] key;

	/**
	 * Creates a key instance. Should only be used by the
	 * S2KKeyGenerator class.
	 */
	public S2KSecretKey(int algorithm, byte[] key) {
		this.algorithm = algorithm;
		this.key = key;
	}

	/*
	 * Overriden to compare key material instead of the entire class.
	 * 
	 * (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof S2KSecretKey) {
			S2KSecretKey other = (S2KSecretKey)obj;
			return Arrays.equals(key, other.key);
		}
		else {
			return false;
		}
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return KeyAlgorithms.SYMMETRIC_NAMES[algorithm];
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return "S2K";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		return key;
	}

	/*
	 * Overriden to create the hash based on the key material.
	 * 
	 * (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return key.hashCode();
	}

}
