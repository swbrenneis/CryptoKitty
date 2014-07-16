/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * Shell class for the SHA256 digest
 * 
 */
public class SHA256Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public SHA256Hash() throws NoSuchAlgorithmException {
		super("SHA-256");
	}

}
