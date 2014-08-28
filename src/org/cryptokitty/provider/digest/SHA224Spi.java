/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA224Spi extends DigestSpi {

	/**
	 * 
	 */
	public SHA224Spi() {
		super(new CKSHA224());
	}

}
