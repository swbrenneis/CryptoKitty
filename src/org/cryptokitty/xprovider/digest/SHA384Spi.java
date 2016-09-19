/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.SHA384;

/**
 * @author Steve Brenneis
 *
 */
public class SHA384Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA384Spi() {

		digest = new SHA384();

	}

}
