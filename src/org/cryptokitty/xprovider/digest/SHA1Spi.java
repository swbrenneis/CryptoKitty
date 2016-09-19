/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.SHA1;

/**
 * @author SteveBrenneis
 *
 */
public class SHA1Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA1Spi() {

		digest = new SHA1();

	}

}
