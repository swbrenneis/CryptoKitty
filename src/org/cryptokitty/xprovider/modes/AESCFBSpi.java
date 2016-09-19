/**
 * 
 */
package org.cryptokitty.xprovider.modes;

import org.cryptokitty.xprovider.cipher.AES;

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
