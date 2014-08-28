/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class MD5Spi extends DigestSpi {

	/**
	 * 
	 */
	public MD5Spi() {
		super(new CKMD5());
	}

}
