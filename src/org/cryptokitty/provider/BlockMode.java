/**
 * 
 */
package org.cryptokitty.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.ShortBufferException;

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
			throws IOException, ShortBufferException;

	/*
	 * Encrypt a series of bits.
	 */
	public void encrypt(InputStream cleartext, OutputStream ciphertext)
			throws IOException, ShortBufferException;

	/*
	 * Reset the mode.
	 */
	public void reset();

}
