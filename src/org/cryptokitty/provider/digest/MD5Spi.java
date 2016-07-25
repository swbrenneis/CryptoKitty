/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class MD5Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public MD5Spi() {
		
		digest = new CKMD5();

	}

}
