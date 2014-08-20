/**
 * 
 */
package org.cryptokitty.digest;

import java.security.DigestException;

import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;

/**
 * @author Steve Brenneis
 *
 * Delegate class implementation.
 */
public abstract class HashImpl {

	/*
	 * The message digest.
	 */
	protected Digest digest;

	/**
	 * 
	 */
	protected HashImpl(String algorithm)
			throws UnsupportedAlgorithmException {
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest()
	 */
	//@Override
	public byte[] digest() {
		return digest.digest();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest(byte[])
	 */
	//@Override
	public byte[] digest(byte[] input) {
		return digest.digest(input);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#digest(byte[], int, int)
	 */
	//@Override
	//public byte[] digest(byte[] input, int offset, int length)
	//		throws DigestException {
	//	return digest.digest(input, offset, length);
	//}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#getDigestLength()
	 */
	//@Override
	//public int getDigestLength() {
	//	return digest.getDigestLength();
	//}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#reset()
	 */
	//@Override
	public void reset() {
		//digest.reset();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte)
	 */
	//@Override
	public void update(byte input) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte[])
	 */
	//@Override
	public void update(byte[] input) {
		digest.update(input);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.digest.Hash#update(byte[], int, int)
	 */
	//@Override
	public void update(byte[] input, int offset, int length) {
		digest.update(input, offset, length);
	}

}
