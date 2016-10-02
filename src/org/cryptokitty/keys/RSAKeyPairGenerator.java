/**
 * 
 */
package org.cryptokitty.keys;

import java.security.KeyPair;

/**
 * @author Steve Brenneis
 *
 * This class generates the CRT version of the private key by
 * default. The (n, d) version can be specified in the
 * algorithm parameters.
 */
public class RSAKeyPairGenerator {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * JNI implementation pointer.
	 */
	private long jniImpl;

	/**
	 * 
	 */
	public RSAKeyPairGenerator() {

		jniImpl = initialize();

	}

	/**
	 * Free JNI resources.
	 */
	private native void dispose();

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	public void finalize() throws Throwable {

		dispose();

	}

	/**
	 * Default initialization.
	 */
	private native long initialize();

	/**
	 * 
	 * @param keysize
	 * @param random
	 */
	public native void initialize(int keysize);

	/**
	 * 
	 * @return
	 */
	public native KeyPair generateKeyPair() throws IllegalStateException;

}
