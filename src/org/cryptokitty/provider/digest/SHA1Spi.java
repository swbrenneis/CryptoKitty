/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author SteveBrenneis
 *
 */
public class SHA1Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA1Spi() {

		digest = new CKSHA1();

	}

}
