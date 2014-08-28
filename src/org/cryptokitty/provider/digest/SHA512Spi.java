/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA512Spi extends DigestSpi {

	/**
	 * 
	 */
	public SHA512Spi() {
		super(new CKSHA512());
	}

}
