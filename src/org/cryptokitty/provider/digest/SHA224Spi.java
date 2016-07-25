/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA224Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA224Spi() {

		digest = new CKSHA224();

	}

}
