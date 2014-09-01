/**
 * 
 */
package org.cryptokitty.provider.signature;

import org.cryptokitty.provider.UnsupportedAlgorithmException;



/**
 * @author stevebrenneis
 *
 */
public class SHA512RSASignature extends RSASignature {

	/**
	 * Creates a new EMSA-PSS signature object using SHA512 hash
	 * and salt length of 8. The exception is actually ignored
	 * because the classes are limited to known hash algorithms.
	 */
	public SHA512RSASignature()
			throws UnsupportedAlgorithmException {
		super(new PSSrsassa("SHA-512", 8));
	}

}
