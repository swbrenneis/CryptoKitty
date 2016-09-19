/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.SHA224;

/**
 * @author Steve Brenneis
 *
 */
public class SHA224Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA224Spi() {

		digest = new SHA224();

	}

}
