/**
 * 
 */
package org.cryptokitty.provider.signature;

import org.cryptokitty.provider.UnsupportedAlgorithmException;


/**
 * @author Steve Brenneis
 *
 */
public class SHA384RSASignature extends RSASignature {

	/**
	 * Creates a new EMSA-PSS signature object using SHA384 hash
	 * and salt length of 8. The exception is actually ignored
	 * because the classes are limited to known hash algorithms.
	 */
	public SHA384RSASignature()
			throws UnsupportedAlgorithmException {
		super(new PSSrsassa("SHA-384", 8));
	}

}
