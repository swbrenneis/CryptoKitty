/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA256Spi extends DigestSpi {

	/**
	 * 
	 */
	public SHA256Spi() {
		super(new CKSHA256());
	}

}
