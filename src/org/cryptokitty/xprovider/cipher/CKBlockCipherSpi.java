/**
 * 
 */
package org.cryptokitty.xprovider.cipher;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/**
 * @author stevebrenneis
 *
 */
public class CKBlockCipherSpi extends CipherSpi {

	/**
	 * The cipher stream.
	 */
	protected ByteArrayOutputStream text;
	
	/**
	 * Operation mode. Cipher.ENCRYPT or Cipher.DECRYPT.
	 */
	protected int opmode;

	/**
	 * Encryption/decryption key.
	 */
	protected Key key;
	
	/**
	 * The block cipher.
	 */
	protected BlockCipher cipher;

	/**
	 * Algorithm parameters.
	 */
	protected AlgorithmParameters params;

	/**
	 * Algorithm parameters.
	 */
	protected AlgorithmParameterSpec spec;

	/**
	 * Secure RNG.
	 */
	protected SecureRandom random;

	/**
	 * 
	 */
	public CKBlockCipherSpi() {

		opmode = -1;
		text = new ByteArrayOutputStream();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		
		text.write(input, inputLen, inputLen);
		
		byte[] result = null;
		switch (opmode) {
			case Cipher.DECRYPT_MODE:
				result = cipher.decrypt(text.toByteArray());
			case Cipher.ENCRYPT_MODE:
				result = cipher.encrypt(text.toByteArray());
		}
		
		try {
			engineInit(opmode, key, params, random);
		}
		catch (InvalidKeyException e) {
			// Don't care
		}
		catch (InvalidAlgorithmParameterException e) {
			// Don't care
		}
		return result;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		if (output.length < outputOffset + inputLen) {
			throw new ShortBufferException("Invalid output buffer size");
		}
		
		byte[] result = engineDoFinal(input, inputOffset, inputLen);
		System.arraycopy(result, 0, output, outputOffset, result.length);
		return result.length;
		
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {

		return cipher.getBlockSize();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetIV()
	 * 
	 * No IV used for block ciphers.
	 * 
	 */
	@Override
	protected byte[] engineGetIV() {

		return null;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLen) {

		return cipher.getBlockSize();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {

		return params;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

		this.opmode = opmode;
		this.key = key;
		this.random = random;
		cipher.setKey(key.getEncoded());
		cipher.reset();
		text.reset();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		
		spec = params;
		engineInit(opmode, key, random);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {

		this.params = params;
		engineInit(opmode, key, random);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
	 */
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// Nothing to do here.
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
	 */
	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		// Nothing to do here.
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		// Not used for block ciphers.
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
		// Not used for block ciphers
		return 0;
	}

}
