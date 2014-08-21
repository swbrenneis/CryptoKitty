/**
 * 
 */
package org.cryptokitty.provider;

import org.cryptokitty.pgp.PGPConstants;

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
		super(new PSSrsassa(PGPConstants.SHA384, 8));
	}

}
