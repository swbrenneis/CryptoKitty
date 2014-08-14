/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 *
 * The basic block cipher interface for use in chaining
 * mode classes.
 */
public interface BlockCipher {

	/*
	 * Decrypt a block of ciphertext. Only throws decryption exception
	 * to prevent inadvertent oracles.
	 */
	public byte[] decrypt(byte[] ciphertext)
			throws DecryptionException;

	/*
	 * Encrypt a block of plaintext.
	 */
	public byte[] encrypt(byte[] plaintext)
			throws ProviderException;

	/*
	 * Get the cipher block size in bytes. Throws an exception if the
	 * size cannot be determined.
	 */
	public int getBlockSize() throws ProviderException;

}
