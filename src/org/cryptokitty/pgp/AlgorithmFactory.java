/**
 * 
 */
package org.cryptokitty.pgp;

import org.cryptokitty.digest.MD5;
import org.cryptokitty.digest.SHA224;
import org.cryptokitty.digest.SHA256;
import org.cryptokitty.digest.SHA384;
import org.cryptokitty.digest.SHA512;
import org.cryptokitty.digest.Digest;
import org.cryptokitty.xprovider.UnsupportedAlgorithmException;
import org.cryptokitty.xprovider.digest.CKRIPEMD160;

/**
 * @author Steve Brenneis
 *
 * Handles factory methods for provider algorithms.
 */
public class AlgorithmFactory {

	/*
	 * Hash classes.
	 */
	public static Digest getDigest(int algorithm)
		throws UnsupportedAlgorithmException {

		switch (algorithm) {
		case PGPConstants.MD5:
			return new MD5();
		case PGPConstants.RIPEMD160:
			return new CKRIPEMD160();
		case PGPConstants.SHA224:
			return new SHA224();
		case PGPConstants.SHA256:
			return new SHA256();
		case PGPConstants.SHA384:
			return new SHA384();
		case PGPConstants.SHA512:
			return new SHA512();
		default:
			throw new UnsupportedAlgorithmException("No such hash algorithm: "
												+ String.valueOf(algorithm));
		}

	}
	/**
	 * 
	 */
	protected AlgorithmFactory() {
		// TODO Auto-generated constructor stub
	}

}
