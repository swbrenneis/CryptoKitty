package org.cryptokitty.provider.modes;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.cipher.BlockCipher;
import org.cryptokitty.provider.cipher.DecryptionException;

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
	 * @param cipher
	 * @param iv
	 */
	public CFB(BlockCipher cipher, byte[] iv)
		throws ProviderException {
		this.cipher = cipher;
		blockSize = cipher.getBlockSize();
		this.iv = iv;
		feedback = Arrays.copyOf(iv, iv.length);
	}

	@Override
	public void decrypt(InputStream cipherstream, OutputStream plainstream)
			throws DecryptionException {
		try {
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
		catch (IOException e) {
			throw new DecryptionException();
		}
		catch (ProviderException e) {
			throw new DecryptionException();
		}
	}

	@Override
	public void encrypt(InputStream plainstream, OutputStream cipherstream)
			throws ProviderException {
		try {
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
		catch (IOException e) {
			throw new ProviderException("Invalid message stream operation");
		}
	}

	@Override
	public void reset() {
		feedback = Arrays.copyOf(iv, iv.length);
	}

	/*
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