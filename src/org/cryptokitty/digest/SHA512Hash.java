/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * Shell class for the SHA512 digest.
 */
public class SHA512Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public SHA512Hash() throws NoSuchAlgorithmException {
		super("SHA-512");
	}

}
