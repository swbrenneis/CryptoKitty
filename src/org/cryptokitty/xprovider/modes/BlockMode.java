/**
 * 
 */
package org.cryptokitty.xprovider.modes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.xprovider.cipher.BlockCipher;

/**
 * @author Steve Brenneis
 *
 * Block mode interface for use in the JCA Cipher classes.
 */
public interface BlockMode {

	/**
	 * Decrypt a series of bits.
	 */
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws IllegalBlockSizeException, BadPaddingException, IOException;

	/*
	 * Encrypt a series of bits.
	 */
	public void encrypt(InputStream plaintext, OutputStream ciphertext)
			throws IllegalBlockSizeException, BadPaddingException, IOException;

	/**
	 * Get the block size of the underlying cipher.
	 * @return
	 */
	public int getBlockSize();

	/**
	 * Get the initialization vector.
	 */
	byte[] getIV();

	/**
	 * Reset the mode.
	 */
	public void reset();

	/**
	 * Set the block cipher.
	 */
	public void setBlockCipher(BlockCipher cipher);

	/**
	 * Set the initialization vector.
	 */
	public void setIV(byte[] iv);
	
	/**
	 * Set the encryption/decryption key.
	 */
	void setKey(byte[] key) throws InvalidKeyException;

	/**
	 * Set the algorithm parameters
	 */
	void setParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException;
	
}
