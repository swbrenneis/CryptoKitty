/**
 * 
 */
package org.cryptokitty.modes;

import org.cryptokitty.exceptions.AuthenticationException;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;

/**
 * @author stevebrenneis
 *
 */
public interface AEADCipherMode {

	/**
	 * Decrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 * @throws BadParameterException 
	 */
	public byte[] decrypt(byte[] ciphertext, byte[] key)
				throws AuthenticationException, IllegalBlockSizeException,
												BadParameterException;

	/**
	 * Encrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 * @throws BadParameterException 
	 */
	public byte[] encrypt(byte[] plaintext, byte[] key)
				throws IllegalBlockSizeException, BadParameterException;

	/**
	 * Set the AEAD authentication data.
	 * 
	 * @param authData
	 */
	public void setAuthenticationData(byte[] authData);

	
	/**
	 * Set the initial value.
	 * @param iv
	 */
	public void setIV(byte[] iv);

}
