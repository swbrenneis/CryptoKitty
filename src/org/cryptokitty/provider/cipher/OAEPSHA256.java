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
public class OAEPSHA256 extends RSACipherSpi {

	/**
	 * 
	 */
	public OAEPSHA256() {
		
		rsa = new OAEPrsaes();
		try {
			rsa.setHashAlgorithm("SHA-256");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Nope.
		}

	}

}
