/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * Shell class for the SHA384 digest.
 * SHA384 is just a truncation of the SHA512 hash.
 */
public class SHA384Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public SHA384Hash() throws NoSuchAlgorithmException {
		super("SHA-384");
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#digest()
	 */
	@Override
	public byte[] digest() {
		byte[] h256 = digest.digest();
		return Arrays.copyOfRange(h256, 0, 47);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#digest(byte[])
	 */
	@Override
	public byte[] digest(byte[] input) {
		byte[] h256 = digest.digest(input);
		return Arrays.copyOfRange(h256, 0, 47);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.digest.HashImpl#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 48;
	}

}
