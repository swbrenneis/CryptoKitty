/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.SHA512;

/**
 * @author Steve Brenneis
 *
 */
public class SHA512Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA512Spi() {

		digest = new SHA512();

	}

}
