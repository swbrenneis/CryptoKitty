/**
 * 
 */
package org.cryptokitty.provider.cipher;

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
