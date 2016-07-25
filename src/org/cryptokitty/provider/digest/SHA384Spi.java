/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA384Spi extends CKMessageDigestSpi {

	/**
	 * 
	 */
	public SHA384Spi() {

		digest = new CKSHA384();

	}

}
