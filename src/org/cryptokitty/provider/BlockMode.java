/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 *
 * Block mode interface for use in the JCA Cipher classes.
 */
public interface BlockMode {

	/*
	 * Decrypt a series of bits.
	 */
	public byte[] decrypt(byte[] ciphertext);

	/*
	 * Encrypt a series of bits.
	 */
	public byte[] encrypt(byte[] cleartext);

	/*
	 * Reset the mode.
	 */
	public void reset();

}
