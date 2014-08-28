/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class SHA384Spi extends DigestSpi {

	/**
	 * 
	 */
	public SHA384Spi() {
		super(new CKSHA384());
	}

}
