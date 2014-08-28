/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author SteveBrenneis
 *
 */
public class SHA1Spi extends DigestSpi {

	/**
	 * 
	 */
	public SHA1Spi() {
		super(new CKSHA1());
	}

}
