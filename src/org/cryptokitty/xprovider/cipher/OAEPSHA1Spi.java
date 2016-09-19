/**
 * 
 */
package org.cryptokitty.xprovider.cipher;

import org.cryptokitty.cipher.OAEPrsaes;

/**
 * @author stevebrenneis
 *
 */
public class OAEPSHA1Spi extends RSACipherSpi {

	/**
	 * 
	 */
	public OAEPSHA1Spi() {
		
		rsa = new OAEPrsaes();
/*		try {
			rsa.setHashAlgorithm("SHA-1");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Nope.
		}
*/		
	}

}
