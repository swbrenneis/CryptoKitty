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

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.cryptokitty.data.Scalar32;

/**
 * @author Steve Brenneis
 *
 * Implementation of the CAST-128 cipher (aka CAST5).
 * See RFC 2144 for details.
 */
public class CAST5Cipher extends CipherSpi {

	/*
	 * Byte array for holding intermediate results.
	 */
	private byte[] intermediate;

	/*
	 * Initialization vector for feedback chaining modes.
	 */
	private byte[] iv;

	/*
	 * The symmetric Key. 128 bits.
	 */
	private Key key;

	/*
	 * Masking key. 32 bits.
	 */
	private long Km;

	/*
	 * Rotation key. 5 bits.
	 */
	private int Kr;

	/**
	 * 
	 */
	public CAST5Cipher() {
		intermediate = new byte[8];
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2)
			throws IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3,
			int arg4) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		// TODO Auto-generated method stub
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
	 * Get the initialization vector used for chaining modes.
	 */
	@Override
	protected byte[] engineGetIV() {
		return iv;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub

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

	/**
	 * Round function 1. See RFC 2144, section 2.2, Non-identical rounds. The
	 * function is given as:
	 * 
	 * I = ((Kmi + D) <<< Kri)
	 * f = ((S1[Ia] ^ S2[Ib]) - S3[Ic]) + S4[Id]
	 */
	private byte[] f1(byte[] d) {
		return null;
	}
}
