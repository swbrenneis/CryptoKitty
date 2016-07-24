/**
 * 
 */
package org.cryptokitty.provider.modes;

import org.cryptokitty.provider.cipher.AES;

/**
 * @author stevebrenneis
 *
 */
public class AESCFBSpi extends CKBlockModeSpi {

	/**
	 * 
	 */
	public AESCFBSpi() {
		
		mode = new CFB();
		mode.setBlockCipher(new AES());
		
	}

}
