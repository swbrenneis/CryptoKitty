/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;

import org.cryptokitty.keys.UnsupportedAlgorithmException;

/**
 * @author Steve Brenneis
 *
 */
public class HashFactory {

	/*
	 * Hash algorithm constants.
	 */
	public static final byte MD5 = 1;
	public static final byte SHA1 = 2;
	public static final byte RIPEMD160 = 3;
	public static final byte SHA256 = 8;
	public static final byte SHA384 = 9;
	public static final byte SHA512 = 10;
	public static final byte SHA224 = 11;

	/*
	 * Return a message digest given an algorithm constant.
	 */
	public static Hash getDigest(byte algorithm)
			throws UnsupportedAlgorithmException {

		try {
			switch(algorithm) {
			case MD5:
				return new MD5Hash();
			case RIPEMD160:
				throw new UnsupportedAlgorithmException(
								"Unsupported hash algorithm - RIPE-MD/160");
			case SHA1:
				return new SHA1Hash();
			case SHA224:
				return new SHA224Hash();
			case SHA256:
				return new SHA256Hash();
			case SHA384:
				return new SHA384Hash();
			case SHA512:
				return new SHA512Hash();
			}
		}
		catch (NoSuchAlgorithmException e) {
			throw new UnsupportedAlgorithmException(e);
		}

		throw new UnsupportedAlgorithmException("Unknown algorithm identifier - "
													+ String.valueOf(algorithm));
	}

	/**
	 * 
	 */
	public HashFactory() {
		// TODO Auto-generated constructor stub
	}

}
