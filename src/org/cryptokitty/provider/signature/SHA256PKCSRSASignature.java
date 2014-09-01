/**
 * 
 */
package org.cryptokitty.provider.signature;

import org.cryptokitty.provider.UnsupportedAlgorithmException;


/**
 * @author Steve Brenneis
 *
 */
public class SHA256PKCSRSASignature extends RSASignature {

	/**
	 * Creates a new EMSA-PKCS signature object using SHA256 hash.
	 * The exception is actually ignored because the classes are
	 * limited to known hash algorithms.
	 */
	public SHA256PKCSRSASignature()
			throws UnsupportedAlgorithmException {
		super(new PKCS1rsassa("SHA-256"));
	}

}
