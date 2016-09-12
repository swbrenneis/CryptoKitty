/**
 * 
 */
package org.cryptokitty.provider.cipher;

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
