/**
 * 
 */
package org.cryptokitty.provider;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * CipherSpi for the RSA Cipher class.
 */
public class RSACipher extends CipherSpi {

	/*
	 * Input octet string accumulator.
	 */
	private ByteArrayOutputStream accumulator;
	
	/*
	 * Block mode. Will be ECB.
	 */
	private BlockMode mode;

	/*
	 * Operation mode. One of Cipher.ENCRYPT or Cipher.DECRYPT.
	 */
	int opmode;

	/*
	 * The private key.
	 */
	private RSA.PrivateKey privateKey;

	/*
	 * The private key.
	 */
	private RSA.PublicKey publicKey;

	/*
	 * The cipher implementation.
	 */
	private RSA rsa;

	/**
	 * 
	 */
	public RSACipher() {
		opmode = -1;
		rsa = null;
		publicKey = null;
		privateKey = null;
		mode = null;
		accumulator = new ByteArrayOutputStream();
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		if (rsa == null) {
			throw new BadPaddingException("Padding not set");
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {

		if (rsa == null) {
			throw new BadPaddingException("Padding not set");
		}

		return 0;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetBlockSize()
	 */
	@Override
	protected int engineGetBlockSize() {
		// RSA isn't a block cipher, but Java doesn't care.
		// Raw RSA always returns k (key size in bytes).
		return opmode == Cipher.ENCRYPT_MODE ? publicKey.bitsize / 8
												: privateKey.bitsize / 8;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetIV()
	 */
	@Override
	protected byte[] engineGetIV() {
		// TODO ECB?
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
	 */
	@Override
	protected int engineGetOutputSize(int inputLen) {
		if (mode == null) {
			// Raw RSA always returns k (key size in bytes).
			return opmode == Cipher.ENCRYPT_MODE ? publicKey.bitsize / 8
													: privateKey.bitsize / 8;
		}
		else {
			// TODO Implement ECB
			return -1;
		}
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
		// We won't use the passed in SecureRandom. Potential security risk!
		// The default RSA implementation is OAEP encoding with SHA-256.
		try {
			rsa = new OAEPrsaes(HashFactory.SHA256);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen.
		}

		// Set up the appropriate key.
		setKey(key);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec param,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		// There is no applicable AlgorithmParameterSpec class.
		this.opmode = opmode;
		// We won't use the passed in SecureRandom. Potential security risk!
		// The default RSA implementation is OAEP encoding with SHA-256.
		try {
			rsa = new OAEPrsaes(HashFactory.SHA256);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen.
		}

		// Set up the appropriate key.
		setKey(key);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key, java.security.AlgorithmParameters, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		// There is no applicable AlgorithmParameters class.
		this.opmode = opmode;
		// We won't use the passed in SecureRandom. Potential security risk!
		// The default RSA implementation is OAEP encoding with SHA-256.
		try {
			rsa = new OAEPrsaes(HashFactory.SHA256);
		}
		catch (UnsupportedAlgorithmException e) {
			// Won't happen.
		}

		// Set up the appropriate key.
		setKey(key);

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
	 */
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// TODO Implement ECB mode.
		throw new NoSuchAlgorithmException(mode + " not supported");
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
	 */
	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {

		try {
			switch (padding) {
			case "PKCS1Padding":
				rsa = new PKCS1rsaes();
				break;
			case "OAEPWithSHA-1AndMGF1Padding":
				rsa = new OAEPrsaes(HashFactory.SHA1);
				break;
			case "OAEPWithSHA-256AndMGF1Padding":
				rsa = new OAEPrsaes(HashFactory.SHA256);
				break;
			case "OAEPWithSHA-384AndMGF1Padding":
				rsa = new OAEPrsaes(HashFactory.SHA384);
				break;
			case "OAEPWithSHA-512AndMGF1Padding":
				rsa = new OAEPrsaes(HashFactory.SHA512);
				break;
			default:
				rsa = null;
				throw new NoSuchPaddingException("Invalid padding: " + padding);
			}
		}
		catch (UnsupportedAlgorithmException e) {
			// Shouldn't happen, but...
			rsa = null;
			throw new NoSuchPaddingException("Invalid hash algorithm");
		}

	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {
		// TODO Auto-generated method stub
		return 0;
	}

	/*
	 * Set up the appropriate key. Assumes that opmode has been set.
	 */
	private void setKey(Key key) throws InvalidKeyException {

		switch (opmode) {
		case Cipher.ENCRYPT_MODE:
			if (key instanceof RSAPublicKey) {
				publicKey = rsa.new PublicKey();
				publicKey.n = ((RSAPublicKey) key).getModulus();
				publicKey.e = ((RSAPublicKey) key).getPublicExponent();
				publicKey.bitsize = publicKey.n.bitLength();
			}
			else {
				throw new InvalidKeyException("Not a valid RSA public key");
			}
			break;
		case Cipher.DECRYPT_MODE:
			if (key instanceof RSAPrivateCrtKey) {
				RSA.CRTPrivateKey crt = rsa.new CRTPrivateKey();
				crt.p = ((RSAPrivateCrtKey) key).getPrimeP();
				crt.q = ((RSAPrivateCrtKey) key).getPrimeQ();
				crt.dP = ((RSAPrivateCrtKey) key).getPrimeExponentP();
				crt.dQ = ((RSAPrivateCrtKey) key).getPrimeExponentQ();
				crt.qInv = ((RSAPrivateCrtKey) key).getCrtCoefficient();
				BigInteger n = crt.p.multiply(crt.q);
				privateKey.bitsize = n.bitLength();
				privateKey = crt;
			}
			else if (key instanceof RSAPrivateKey) {
				RSA.ModulusPrivateKey mod = rsa.new ModulusPrivateKey();
				mod.n = ((RSAPrivateKey) key).getModulus();
				mod.d = ((RSAPrivateKey) key).getPrivateExponent();
				privateKey.bitsize = mod.n.bitLength();
				privateKey = mod;
			}
			else {
				throw new InvalidKeyException("Not a valid RSA private key");
			}
			break;
		}

	}

}
