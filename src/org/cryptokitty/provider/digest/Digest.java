/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 * Basic interface contract for all Crypto Kitty hashes.
 */
public interface Digest {

	/*
	 * Finish a previously updated digest.
	 */
	public byte[] digest();

	/*
	 * One step hash. Previous updates to the context are ignored.
	 */
	public byte[] digest(byte[] message);

	/*
	 * Update the hash context.
	 */
	public void update(byte message);

	/*
	 * Update the hash context.
	 */
	public void update(byte[] message);

	/*
	 * Update the hash context.
	 */
	public void update(byte[] message, int offset, int length);

}
