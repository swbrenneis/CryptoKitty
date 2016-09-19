/**
 * 
 */
package org.cryptokitty.xprovider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class RIPEMD160Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public RIPEMD160Spi() {

		digest = new CKRIPEMD160();

	}

}
