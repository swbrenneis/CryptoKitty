/**
 * 
 */
package org.cryptokitty.provider.signature;

import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.cipher.PSSrsassa;



/**
 * @author Steve Brenneis
 *
 */
public class SHA1RSASignature extends RSASignature {

	/**
	 * Creates a new EMSA-PSS signature object using SHA-1 hash
	 * and salt length of 8. The exception is actually ignored
	 * because the classes are limited to known hash algorithms.
	 */
	public SHA1RSASignature()
			throws UnsupportedAlgorithmException {
		super(new PSSrsassa("SHA-1", 8));
	}

}
