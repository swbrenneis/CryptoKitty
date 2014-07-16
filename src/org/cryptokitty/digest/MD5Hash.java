/**
 * 
 */
package org.cryptokitty.digest;

import java.security.NoSuchAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * MD5 digest shell class.
 * 
 */
public class MD5Hash extends HashImpl {

	/**
	 * @param algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public MD5Hash() throws NoSuchAlgorithmException {
		super("MD5");
	}

}
