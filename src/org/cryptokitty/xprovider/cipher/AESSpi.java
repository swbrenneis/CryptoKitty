/**
 * 
 */
package org.cryptokitty.xprovider.cipher;

/**
 * @author stevebrenneis
 *
 */
public class AESSpi extends CKBlockCipherSpi {

	/**
	 * 
	 */
	public AESSpi() {
		
		cipher = new AES();

	}

}
