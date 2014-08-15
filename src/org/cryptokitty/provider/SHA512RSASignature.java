/**
 * 
 */
package org.cryptokitty.provider;

import org.cryptokitty.digest.HashFactory;

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
		super(new PSSrsassa(HashFactory.SHA512, 8));
	}

}
