/**
 * 
 */
package org.cryptokitty.provider.cipher;

/**
 * @author stevebrenneis
 *
 */
public class OAEPSHA256 extends RSACipherSpi {

	/**
	 * 
	 */
	public OAEPSHA256() {
		
		System.out.println("OAEPSHA256");
		rsa = new OAEPrsaes();
		/*try {
			rsa.setHashAlgorithm("SHA-256");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Nope.
			System.out.println("Provider SHA-256 hash not found");
		}*/

	}

}
