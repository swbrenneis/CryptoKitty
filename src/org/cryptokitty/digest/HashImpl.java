/**
 * 
 */
package org.cryptokitty.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * Delegate class implementation.
 */
public abstract class HashImpl implements Hash {

	/*
	 * The message digest.
	 */
	protected MessageDigest digest;

	/**
	 * 
	 */
	protected HashImpl(String algorithm)
			throws NoSuchAlgorithmException {
		digest = MessageDigest.getInstance(algorithm);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest()
	 */
	@Override
	public byte[] digest() {
		return digest.digest();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest(byte[])
	 */
	@Override
	public byte[] digest(byte[] input) {
		return digest.digest(input);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest(byte[], int, int)
	 */
	@Override
	public int digest(byte[] input, int offset, int length)
			throws DigestException {
		return digest.digest(input, offset, length);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return digest.getDigestLength();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#reset()
	 */
	@Override
	public void reset() {
		digest.reset();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte)
	 */
	@Override
	public void update(byte input) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte[])
	 */
	@Override
	public void update(byte[] input) {
		digest.update(input);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte[], int, int)
	 */
	@Override
	public void update(byte[] input, int offset, int length) {
		digest.update(input, offset, length);
	}

}
