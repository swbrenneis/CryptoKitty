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
	 * Decrypt a block of ciphertext.
	 */
	public byte[] decrypt(byte[] ciphertext)
			throws DecryptionException;

	/*
	 * Encrypt a block of plaintext.
	 */
	public byte[] encrypt(byte[] plaintext);

	/*
	 * Get the cipher block size in bytes.
	 */
	public int getBlockSize();

}
