/**
 * 
 */
package org.cryptokitty.random;

import java.nio.ByteBuffer;

/**
 * @author stevebrenneis
 *
 */
public class FortunaSecureRandom extends SecureRandomWrapper implements SecureRandom {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -3455700191950379176L;

	/**
	 * 
	 */
	public FortunaSecureRandom() {
	}

	/**
	 * 
	 * @param bytes
	 */
	public native void nextBytes(byte[] bytes);

	/**
	 * 
	 * @return
	 */
	public int nextInt() {

		byte[] bytes = new byte[4];
		nextBytes(bytes);
		ByteBuffer wrapper = ByteBuffer.wrap(bytes);
		return wrapper.getInt();

	}

	/**
	 * 
	 * @return
	 */
	public long nextLong() {

		byte[] bytes = new byte[8];
		nextBytes(bytes);
		ByteBuffer wrapper = ByteBuffer.wrap(bytes);
		return wrapper.getLong();

	}

}
