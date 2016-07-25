package org.cryptokitty.provider.modes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.provider.cipher.BlockCipher;

/**
 * @author Steve Brenneis
 *
 */
public class CFB implements BlockMode {

	/*
	 * The cipher block size.
	 */
	private int blockSize;

	/*
	 * The block cipher.
	 */
	private BlockCipher cipher;
	
	/*
	 * The feedback register.
	 */
	private byte[] feedback;

	/*
	 * The initialization vector.
	 */
	private byte[] iv;

	/**
	 * 
	 */
	public CFB() {
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#decrypt()
	 */
	@Override
	public void decrypt(InputStream cipherstream, OutputStream plainstream)
			throws IllegalBlockSizeException, BadPaddingException, IOException {

		byte[] ciphertext = new byte[blockSize];
		int read = cipherstream.read(ciphertext);
		while (read > 0) {
			byte[] cipherblock = cipher.encrypt(feedback);
			byte[] plaintext = xor(ciphertext, cipherblock);
			feedback = Arrays.copyOf(ciphertext, read);
			plainstream.write(Arrays.copyOf(plaintext, read));
			read = cipherstream.read(ciphertext);
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#encrypt()
	 */
	@Override
	public void encrypt(InputStream plainstream, OutputStream cipherstream)
			throws IllegalBlockSizeException, BadPaddingException, IOException {

		byte[] plaintext = new byte[blockSize];
		int read = plainstream.read(plaintext);
		while (read > 0) {
			byte[] cipherblock = cipher.encrypt(feedback);
			byte[] ciphertext = xor(plaintext, cipherblock);
			feedback = Arrays.copyOf(ciphertext, read);
			cipherstream.write(Arrays.copyOf(ciphertext, read));
			read = plainstream.read(plaintext);
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#getBlockSize()
	 */
	@Override
	public int getBlockSize() {

		return cipher.getBlockSize();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#getIV()
	 */
	@Override
	public byte[] getIV() {
		
		return iv;

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#reset()
	 */
	@Override
	public void reset() {
		
		feedback = Arrays.copyOf(iv, iv.length);
		cipher.reset();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#setBlockCipher()
	 */
	@Override
	public void setBlockCipher(BlockCipher cipher) {

		this.cipher = cipher;

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#setIV()
	 */
	@Override
	public void setIV(byte[] iv) {
		
		this.iv = iv;
		feedback = Arrays.copyOf(iv, iv.length);

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#setKey()
	 */
	@Override
	public void setKey(byte[] key) throws InvalidKeyException {

		cipher.setKey(key);

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.BlockMode#setKey()
	 */
	@Override
	public void setParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
		// Nothing to do.
		
	}

	/**
	 * Exclusive or function.
	 */
	private byte[] xor(byte[] x1, byte[] x2) {
		byte[] result = new byte[x1.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte)(x1[i] ^ x2[i]);
		}
		return result;
	}

}
