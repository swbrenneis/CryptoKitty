/**
 * 
 */
package org.cryptokitty.provider.cipher;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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
		try {
			rsa.setHashAlgorithm("SHA-1");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Nope.
		}
		
	}

}
