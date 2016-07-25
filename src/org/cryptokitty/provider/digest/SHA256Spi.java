/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA256Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA256Spi() {

		digest = new CKSHA256();

	}

}
