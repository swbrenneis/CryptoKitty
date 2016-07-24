/**
 * 
 */
package org.cryptokitty.provider.modes;

import org.cryptokitty.provider.cipher.AES;

/**
 * @author stevebrenneis
 *
 */
public class AESGCMSpi extends CKBlockModeSpi {

	/**
	 * 
	 */
	public AESGCMSpi() {
		
		mode = new GCM();
		mode.setBlockCipher(new AES());

	}

}
