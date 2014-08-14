/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 * 
 * This is a general decryption error exception. It should be
 * used in all decryption schemes. Only the default constructor
 * is visible and the message is always "Decryption error."
 * This model prevents oracles in Cipher classes.
 *
 */
@SuppressWarnings("serial")
public final class DecryptionException extends ProviderException {

	/**
	 * 
	 */
	public DecryptionException() {
		super("Decryption error");
	}

}
