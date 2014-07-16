/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * SHA1 digest shell class.
 */
public class SHA1Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public SHA1Hash() throws NoSuchAlgorithmException {
		super("SHA-1");
	}

}
