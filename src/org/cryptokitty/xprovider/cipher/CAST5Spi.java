/**
 * 
 */
package org.cryptokitty.xprovider.cipher;

/**
 * @author stevebrenneis
 *
 */
public class CAST5Spi extends CKBlockCipherSpi {

	/**
	 * 
	 */
	public CAST5Spi() {

		cipher = new CAST5();

	}

}
