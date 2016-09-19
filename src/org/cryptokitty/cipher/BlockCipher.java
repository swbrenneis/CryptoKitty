/**
 * 
 */
package org.cryptokitty.cipher;

import org.cryptokitty.exceptions.IllegalBlockSizeException;

/**
 * @author stevebrenneis
 *
 */
public interface BlockCipher {

	/**
	 * Decrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(byte[] ciphertext, byte[] key) throws IllegalBlockSizeException;
	
	/**
	 * Encrypt a series of bits.
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] encrypt(byte[] plaintext, byte[] key) throws IllegalBlockSizeException;

	/**
	 * Get the block size of the cipher.
	 * @return
	 */
	public int getBlockSize();

	/**
	 * Reset the cipher state.
	 */
	public void reset();
	
}
