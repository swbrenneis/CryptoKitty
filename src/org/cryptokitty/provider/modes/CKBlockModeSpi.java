/**
 * 
 */
package org.cryptokitty.provider.modes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

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
public class CKBlockModeSpi extends CipherSpi {

	/**
	 * Plaintext stream.
	 */
	private ByteArrayOutputStream text;

	/**
	 * Operation mode. Cipher.ENCRYPT or Cipher.DECRYPT.
	 */
	protected int opmode;

	/**
	 * Encryption/decryption key.
	 */
	protected Key key;
	
	/**
	 * Block mode;
	 */
	protected BlockMode mode;

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
	public CKBlockModeSpi() {

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
		ByteArrayInputStream in = new ByteArrayInputStream(text.toByteArray());
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		
		try {
			switch (opmode) {
				case Cipher.DECRYPT_MODE:
					mode.decrypt(in, out);
				case Cipher.ENCRYPT_MODE:
					mode.encrypt(in, out);
			}
			engineInit(opmode, key, params, random);
		}
		catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
			// Don't care
		}
		return out.toByteArray();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		return 0;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {

		return mode.getBlockSize();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetIV()
	 */
	@Override
	protected byte[] engineGetIV() {

		return mode.getIV();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLen) {
		// This is only used for stream ciphers
		return 0;
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
		mode.setKey(key.getEncoded());
		mode.reset();
		text.reset();

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		
		spec = params;
		mode.setParams(params);
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
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
	 */
	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		
		return null;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {

		return 0;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected void engineUpdateAAD(byte[] src, int offset, int len) {
		
		if (mode instanceof AEADBlockMode) {
			((AEADBlockMode)mode).setAuthenticationData(Arrays.copyOfRange(src, offset, offset + len));
		}
		// Otherwise do nothing. Silly programmer.

	}

}
