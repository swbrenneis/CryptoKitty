/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.SHA256;

/**
 * @author Steve Brenneis
 *
 */
public class SHA256Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA256Spi() {

		digest = new SHA256();

	}

}
