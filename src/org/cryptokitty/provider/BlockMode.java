/**
 * 
 */
package org.cryptokitty.provider;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author Steve Brenneis
 *
 * Block mode interface for use in the JCA Cipher classes.
 */
public interface BlockMode {

	/*
	 * Decrypt a series of bits.
	 */
	public void decrypt(InputStream ciphertext, OutputStream plaintext)
			throws DecryptionException;

	/*
	 * Encrypt a series of bits.
	 */
	public void encrypt(InputStream plaintext, OutputStream ciphertext)
			throws ProviderException;

	/*
	 * Reset the mode.
	 */
	public void reset();

}
