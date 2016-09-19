/**
 * 
 */
package org.cryptokitty.random;

/**
 * @author stevebrenneis
 *
 */
public interface SecureRandom {
	
	/**
	 * 
	 * @return The next 32 bits of entropy.
	 */
	public int nextInt();

	/**
	 * 
	 * @return The next 64 bits of entropy.
	 */
	public long nextLong();

	/**
	 * Fills a byte array with entropy.
	 * 
	 * @param bytes
	 */
	public void nextBytes(byte[] bytes);

}
