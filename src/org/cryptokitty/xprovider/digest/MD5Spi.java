/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import org.cryptokitty.digest.MD5;

/**
 * @author Steve Brenneis
 *
 */
public class MD5Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public MD5Spi() {
		
		digest = new MD5();

	}

}
