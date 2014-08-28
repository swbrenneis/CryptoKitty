/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class RIPEMD160Spi extends DigestSpi {

	/**
	 * 
	 */
	public RIPEMD160Spi() {
		super(new CKRIPEMD160());
	}

}
