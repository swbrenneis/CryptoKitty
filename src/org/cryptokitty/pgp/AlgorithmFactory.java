/**
 * 
 */
package org.cryptokitty.pgp;

import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.CKMD5;
import org.cryptokitty.provider.digest.CKRIPEMD160;
import org.cryptokitty.provider.digest.CKSHA224;
import org.cryptokitty.provider.digest.CKSHA256;
import org.cryptokitty.provider.digest.CKSHA384;
import org.cryptokitty.provider.digest.CKSHA512;
import org.cryptokitty.provider.digest.Digest;

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
			return new CKMD5();
		case PGPConstants.RIPEMD160:
			return new CKRIPEMD160();
		case PGPConstants.SHA224:
			return new CKSHA224();
		case PGPConstants.SHA256:
			return new CKSHA256();
		case PGPConstants.SHA384:
			return new CKSHA384();
		case PGPConstants.SHA512:
			return new CKSHA512();
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
