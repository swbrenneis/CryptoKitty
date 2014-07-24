/**
 * 
 */
package org.cryptokitty.provider;

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
import javax.crypto.spec.IvParameterSpec;

/**
 * @author Steve Brenneis
 *
 */
public class CAST5Cipher extends CipherSpi {

	/*
	 * The cipher implementation.
	 */
	private CAST5 cast5;

	/*
	 * Initialization vector parameter.
	 */
	private IvParameterSpec iv;

	/*
	 * Cipher operation mode. Will be one of Cipher.ENCRYPT_MODE,
	 * Cipher.DECRYPT_MODE, Cipher.WRAP_KEY, or Cipher.UNWRAP_KEY
	 */
	private int opmode;

	/*
	 * Algorithm parameters.
	 */
	private AlgorithmParameters params;

	/**
	 * 
	 * Creates an empty an uninitialized cipher.
	 */
	public CAST5Cipher() {
		opmode = 0; // Undefined.
		params = null;
		iv = null;
		cast5 = null;
	}

	/*
	 * One step encryption/decryption. Block size must be 8.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLength)
			throws IllegalBlockSizeException, BadPaddingException {
		return null;
	}

	/*
	 * One step encyption/decryption. Block size must be 8.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLength, byte[] output,
			int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		return 0;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {
		return 8;
	}

	/*
	 * No IV is used in the simple block cipher.
	 */
	@Override
	protected byte[] engineGetIV() {
		return iv.getIV();
	}

	/*
	 * Inputs and outputs are always 8 for the simple block cipher.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLength) {
		return 8;
	}

	/*
	 * No algorithm parameters are stored in the simple cipher.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {
		return params;
	}

	/*
	 * Initializes the cipher using the specified key. The secure random
	 * is used to generate the initialization vector.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		byte[] ivBytes = new byte[8];
		random.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);

	}

	/*
	 * Initializes the cipher using the specified key and IV parameter. Throws an
	 * exception if the IV parameter is missing. The secure random is ignored.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		if (params != null && params instanceof IvParameterSpec) {
			iv = (IvParameterSpec)params;
		}
		else {
			throw new InvalidAlgorithmParameterException("Expecting initialization vector");
		}

	}

	/*
	 * Initializes the cipher using the specified key and parameters. The
	 * secure random is used to generate the initialization vector.
	 * 
	 *  (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		this.opmode = opmode;
		cast5 = new CAST5(key);
		this.params = params;
		byte[] ivBytes = new byte[8];
		random.nextBytes(ivBytes);
		iv = new IvParameterSpec(ivBytes);

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
	protected byte[] engineUpdate(byte[] arg0, int arg1, int arg2) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3,
			int arg4) throws ShortBufferException {
		// TODO Auto-generated method stub
		return 0;
	}

}
