/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * SHA224 digest shell class. A SHA224 hash is just a truncated SHA256 hash.
 */
public class SHA224Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public SHA224Hash() throws NoSuchAlgorithmException {
		super("SHA-256");
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#digest()
	 */
	@Override
	public byte[] digest() {
		byte[] h256 = digest.digest();
		return Arrays.copyOfRange(h256, 0, 27);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#digest(byte[])
	 */
	@Override
	public byte[] digest(byte[] input) {
		byte[] h256 = digest.digest(input);
		return Arrays.copyOfRange(h256, 0, 27);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 28;
	}

}
