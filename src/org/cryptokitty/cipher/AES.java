/**
 * 
 */
package org.cryptokitty.cipher;

import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidKeyException;

/**
 * @author stevebrenneis
 *
 */
public class AES implements BlockCipher {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * Key size enumerators.
	 */
	public static final int AES128 = 16;
	public static final int AES192 = 24;
	public static final int AES256 = 32;

	/**
	 * JNI implementation pointer.
	 */
	private long jniImpl;

	/**
	 * @throws InvalidKeyException 
	 * 
	 */
	public AES(int keySize) throws InvalidKeyException {

		switch (keySize) {
			case AES128:
			case AES192:
			case AES256:
				jniImpl = initialize(keySize);
				break;
			default:
				throw new InvalidKeyException("Invalid AES key size");
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#decrypt(byte[], byte[])
	 */
	@Override
	public native byte[] decrypt(byte[] ciphertext, byte[] key)
							throws BadParameterException, IllegalBlockSizeException;

	/**
	 * Free JNI resources.
	 */
	private native void dispose();

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#encrypt(byte[], byte[])
	 */
	@Override
	public native byte[] encrypt(byte[] plaintext, byte[] key)
							throws BadParameterException, IllegalBlockSizeException;

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	public void finalize() throws Throwable {

		dispose();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#getBlockSize()
	 */
	@Override
	public int getBlockSize() {

		return 16;

	}

	/**
	 * JNI implementation initialization.
	 * 
	 * @param keySize
	 */
	private native long initialize(int keySize);

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#reset()
	 */
	@Override
	public native void reset();


}
