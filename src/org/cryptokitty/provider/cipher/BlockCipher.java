package org.cryptokitty.provider.cipher;

import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * @author stevebrenneis
 *
 */
public interface BlockCipher {

	/**
	 * Decrypt a series of bits.
	 */
	public byte[] decrypt(byte[] ciphertext)
			throws IllegalBlockSizeException, BadPaddingException;
	
	/**
	 * Encrypt a series of bits.
	 */
	public byte[] encrypt(byte[] plaintext)
			throws IllegalBlockSizeException, BadPaddingException;

	/**
	 * Get the block size of the cipher.
	 * @return
	 */
	public int getBlockSize();

	/**
	 * Reset the cipher state.
	 */
	public void reset();
	
	/**
	 * Set the encryption/decryption key.
	 */
	void setKey(byte[] key) throws InvalidKeyException;

}
