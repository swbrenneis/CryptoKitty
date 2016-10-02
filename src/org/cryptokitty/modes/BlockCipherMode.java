package org.cryptokitty.modes;

import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;

public interface BlockCipherMode {

	/**
	 * Decrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 * @throws BadParameterException 
	 */
	public byte[] decrypt(byte[] ciphertext, byte[] key)
				throws IllegalBlockSizeException, BadParameterException;

	/**
	 * Encrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 * @throws BadParameterException 
	 */
	public byte[] encrypt(byte[] plaintext, byte[] key)
				throws IllegalBlockSizeException, BadParameterException;

	/**
	 * Set the initial value.
	 * @param iv
	 */
	public void setIV(byte[] iv);

}
