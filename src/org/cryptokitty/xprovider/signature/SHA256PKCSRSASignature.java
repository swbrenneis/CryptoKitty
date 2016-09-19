/**
 * 
 */
package org.cryptokitty.xprovider.signature;


/**
 * @author Steve Brenneis
 *
 */
public class SHA256PKCSRSASignature extends RSASignatureSpi {

	/**
	 * Creates a new EMSA-PKCS signature object using SHA256 hash.
	 * The exception is actually ignored because the classes are
	 * limited to known hash algorithms.
	 */
	public SHA256PKCSRSASignature() {
	}

}
