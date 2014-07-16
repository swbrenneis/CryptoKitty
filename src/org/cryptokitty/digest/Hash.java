/**
 * 
 */
package org.cryptokitty.digest;

import java.security.DigestException;

/**
 * @author Steve Brenneis
 *
 * Delegate interface for the various supported crypto hash
 * algorithms.
 */
public interface Hash {

	/*
	 * Finalize the hash and produce the value.
	 */
	public byte[] digest();

	/*
	 * Update the digest and finalize the result.
	 */
	public byte[] digest(byte[] input);

	/*
	 * Update the digest and finalize the result.
	 */
	public int digest(byte[] input, int offset, int length)
		throws DigestException ;

	/*
	 * Get the size of the hash in bytes.
	 */
	public int getDigestLength();

	/*
	 * Reset the hash algorithm.
	 */
	public void reset();

	/*
	 * Update the digest buffer with one byte.
	 */
	public void update(byte input);

	/*
	 * Update the digest.
	 */
	public void update(byte[] input);

	/*
	 * Update the digest.
	 */
	public void update(byte[] input, int offset, int length);

}
