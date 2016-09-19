/**
 * 
 */
package org.cryptokitty.provider.cipher;

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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.cryptokitty.provider.keys.CKRSAPrivateKey;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * CipherSpi for the RSA Cipher class.
 */
public class RSACipherSpi extends CipherSpi {

	/*
	 * Input octet string accumulator.
	 */
	protected ByteArrayOutputStream accumulator;
	
	/*
	 * Key size in bytes.
	 */
	protected int k;

	/*
	 * Operation mode. One of Cipher.ENCRYPT or Cipher.DECRYPT.
	 */
	protected int opmode;

	/*
	 * The private key.
	 */
	protected CKRSAPrivateKey privateKey;

	/*
	 * The private key.
	 */
	protected CKRSAPublicKey publicKey;

	/*
	 * The cipher implementation.
	 */
	protected RSACipher rsa;

	/**
	 * 
	 */
	public RSACipherSpi() {
		opmode = -1;
		publicKey = null;
		privateKey = null;
		accumulator = new ByteArrayOutputStream();
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		accumulator.write(input, inputOffset, inputLen);

		switch (opmode) {
			case Cipher.DECRYPT_MODE:
				return rsa.decrypt(privateKey, accumulator.toByteArray());
			case Cipher.ENCRYPT_MODE:
				return rsa.encrypt(publicKey, accumulator.toByteArray());
			default:
				return null;
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {

		if (outputOffset + inputLen > output.length) {
			throw new ShortBufferException("Invalid outputbuffer size");
		}
		
		accumulator.write(input, inputOffset, inputLen);

		byte[] text = null;
		switch (opmode) {
		case Cipher.DECRYPT_MODE:
			text = rsa.decrypt(privateKey, accumulator.toByteArray());
		case Cipher.ENCRYPT_MODE:
			text = rsa.encrypt(publicKey, accumulator.toByteArray());
		}

		if (text != null) {
			System.arraycopy(text, 0, output, outputOffset, text.length);
			return text.length;
		}
		else {
			return 0;
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {
		// RSA isn't a block cipher, but Java doesn't care.
		return 0;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetIV()
	 */
	@Override
	protected byte[] engineGetIV() {
		// RSA is not a block cipher and doesn't use an initialization vector.
		return null;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLen) {
		// RSA doesn't use block chaining. This is an irrelevant question.
		// The answer is always k.
		return k;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {
		// AlgorthmParameters are not used.
		return null;

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {

		this.opmode = opmode;
		setKey(key);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec param,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		this.opmode = opmode;
		if (param instanceof OAEPParameterSpec && rsa instanceof OAEPrsaes) {
			OAEPParameterSpec oaepSpec = (OAEPParameterSpec)param;
			OAEPrsaes oaep = (OAEPrsaes)rsa;
			byte[] pSourceBytes;
			PSource pSource = oaepSpec.getPSource();
			if (pSource != null && pSource instanceof PSource.PSpecified) {
				pSourceBytes = ((PSource.PSpecified)oaepSpec.getPSource()).getValue();
				oaep.setPSource(pSourceBytes);
			}
			else {
				throw new InvalidAlgorithmParameterException("Invalid PSource");
			}
/*			try {
				oaep.setHashAlgorithm(oaepSpec.getDigestAlgorithm());
			}
			catch (NoSuchAlgorithmException e) {
				throw new InvalidAlgorithmParameterException("Invalid digest algorithm");
			}
			catch (NoSuchProviderException e) {
				// Won't happen because, well, you know.
			}*/
			if (oaepSpec.getMGFAlgorithm() != "MGF1") {
				throw new InvalidAlgorithmParameterException("Invalid MGF algorithm");
			}
		}
		else if (rsa instanceof PKCS1rsaes && param instanceof IvParameterSpec) {
			PKCS1rsaes rsaes = (PKCS1rsaes)rsa;
			rsaes.setSeed(((IvParameterSpec)param).getIV());
		}
		else {
			throw new InvalidAlgorithmParameterException("OAEP or IV parameter spec expected");
		}

		engineInit(opmode, key, random);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		engineInit(opmode, key, null);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
	 */
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// RSA is not a block cipher and doesn't use block chaining.
		// Mode is ignored.
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
	 */
	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {

		if (rsa instanceof PKCS1rsaes && padding != "PKCS1Padding") {
			throw new NoSuchPaddingException();
		}

		if (rsa instanceof OAEPrsaes && padding != "MGF1Padding") {
			throw new NoSuchPaddingException();
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		// RSA is not a block cipher.
		return null;
	
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {
		// RSA is not a block cipher.
		return 0;

	}

	/*
	 * Set up the appropriate key. Assumes that opmode has been set.
	 */
	private void setKey(Key key) throws InvalidKeyException {

		switch (opmode) {
			case Cipher.ENCRYPT_MODE:
				if (key instanceof CKRSAPublicKey) {
					publicKey = (CKRSAPublicKey)key;
				}
				else {
					throw new InvalidKeyException("Not a valid RSA public key");
				}
				break;
			case Cipher.DECRYPT_MODE:
				if (key instanceof CKRSAPrivateKey) {
					privateKey = (CKRSAPrivateKey)key;
				}
				else {
					throw new InvalidKeyException("Not a valid RSA private key");
				}
				break;
		}

	}

}
