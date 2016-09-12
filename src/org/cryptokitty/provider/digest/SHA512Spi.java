/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA512Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA512Spi() {

		digest = new CKSHA512();

	}

}
