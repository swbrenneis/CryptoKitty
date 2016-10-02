/**
 * 
 */
package org.cryptokitty.modes;

import org.cryptokitty.cipher.BlockCipher;
import org.cryptokitty.exceptions.AuthenticationException;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;

/**
 * @author stevebrenneis
 *
 */
public class GCM implements AEADCipherMode {

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
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public GCM(BlockCipher cipher, boolean appendTag) throws IllegalBlockSizeException {

		if (cipher.getBlockSize() != 16) {
			throw new IllegalBlockSizeException("Invalid GCM block cipher size");
		}

		jniImpl = initialize(cipher, appendTag);

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#decrypt(byte[], byte[])
	 */
	@Override
	public native byte[] decrypt(byte[] ciphertext, byte[] key)
						throws AuthenticationException, IllegalBlockSizeException,
														BadParameterException;

	/**
	 * Free JNI resources.
	 */
	private native void dispose();

	/* (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#encrypt(byte[], byte[])
	 */
	@Override
	public native byte[] encrypt(byte[] P, byte[] key)
							throws IllegalBlockSizeException, BadParameterException;

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	public void finalize() throws Throwable {

		dispose();

	}

	/**
	 * Initialize the JNI implementation.
	 * 
	 * @param cipher
	 * @param appendTag
	 */
	private native long initialize(BlockCipher cipher, boolean appendTag);
	
	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.modes.AEADCipherMode#setAuthenticationData(byte[])
	 */
	@Override
	public native void setAuthenticationData(byte[] authData);

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#setIV(byte[])
	 */
	@Override
	public native void setIV(byte[] iv);

}
