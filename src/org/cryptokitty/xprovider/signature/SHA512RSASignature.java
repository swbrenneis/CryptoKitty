/**
 * 
 */
package org.cryptokitty.xprovider.signature;

/**
 * @author stevebrenneis
 *
 */
public class SHA512RSASignature extends RSASignatureSpi {

	/**
	 * Creates a new EMSA-PSS signature object using SHA512 hash
	 * and salt length of 8. The exception is actually ignored
	 * because the classes are limited to known hash algorithms.
	 */
	public SHA512RSASignature() {
	}

}
