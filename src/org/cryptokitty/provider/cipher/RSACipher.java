/**
 * 
 */
package org.cryptokitty.provider.cipher;

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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;

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
	 * Key size in bytes.
	 */
	private int k;

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
		accumulator = new ByteArrayOutputStream();
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
	 */
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		if (rsa == null) {
			throw new IllegalStateException("Cipher not initialized");
		}
		
		accumulator.write(input, inputOffset, inputLen);

		if (opmode == Cipher.DECRYPT_MODE) {
			try {
				return rsa.decrypt(privateKey, accumulator.toByteArray());
			}
			catch (DecryptionException e) {
				return null;
			}
		}
		else if (opmode == Cipher.ENCRYPT_MODE) {
			try {
				return rsa.encrypt(publicKey, accumulator.toByteArray());
			}
			catch (ProviderException e) {
				// Message size is the only exception we'll get
				throw new IllegalBlockSizeException(e.getMessage());
			}
		}
		else {
			throw new IllegalStateException("Cipher not initialized");
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
			throw new IllegalStateException("Cipher not initialized");
		}
		
		accumulator.write(input, inputOffset, inputLen);

		if (opmode == Cipher.DECRYPT_MODE) {
			try {
				byte[] m = rsa.decrypt(privateKey, accumulator.toByteArray());
				if (output.length - outputOffset > m.length) {
					throw new ShortBufferException("Output buffer too small");
				}
				System.arraycopy(m, 0, output, outputOffset, m.length);
				return m.length;
			}
			catch (DecryptionException e) {
				return 0;
			}
		}
		else if (opmode == Cipher.ENCRYPT_MODE) {
			try {
				byte[] c = rsa.encrypt(publicKey, accumulator.toByteArray());
				if (output.length - outputOffset > c.length) {
					throw new ShortBufferException("Output buffer too small");
				}
				System.arraycopy(c, 0, output, outputOffset, c.length);
				return c.length;
			}
			catch (ProviderException e) {
				// Message size is the only exception we'll get
				throw new IllegalBlockSizeException("Message size too long");
			}
		}
		else {
			throw new IllegalStateException("Cipher not initialized");
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
		// No parameter spec, PKCS1 encoding without seed.
		rsa = new PKCS1rsaes(null);
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
		if (param instanceof OAEPParameterSpec) {
			OAEPParameterSpec oaep = (OAEPParameterSpec)param;
			byte[] pSource;
			if (oaep.getPSource() instanceof PSource.PSpecified) {
				pSource = ((PSource.PSpecified)oaep.getPSource()).getValue();
			}
			else {
				pSource = new byte[0];
			}
			try {
				rsa = new OAEPrsaes(oaep.getDigestAlgorithm(), pSource);
			}
			catch (UnsupportedAlgorithmException e) {
				throw new InvalidAlgorithmParameterException("Invalid hash algorithm: "
															+ oaep.getDigestAlgorithm());
			}
		}
		else if (param instanceof IvParameterSpec) {
			rsa = new PKCS1rsaes(((IvParameterSpec)param).getIV());
		}
		else {
			throw new InvalidAlgorithmParameterException("OAEP or IV parameter spec expected");
		}

		setKey(key);

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

		try {
			switch (padding) {
			case "PKCS1Padding":
				rsa = new PKCS1rsaes(null);
				break;
			case "OAEPWithSHA-1AndMGF1Padding":
				rsa = new OAEPrsaes("SHA-1", new byte[0]);
				break;
			case "OAEPWithSHA-256AndMGF1Padding":
				rsa = new OAEPrsaes("SHA-256", new byte[0]);
				break;
			case "OAEPWithSHA-384AndMGF1Padding":
				rsa = new OAEPrsaes("SHA-384", new byte[0]);
				break;
			case "OAEPWithSHA-512AndMGF1Padding":
				rsa = new OAEPrsaes("SHA-512", new byte[0]);
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
		// RSA is not a block cipher. This does exactly the same thing as engineDoFinal.
		// It is important to note that there are no exceptions thrown from this method,
		// so it should be avoided.
		try {
			return engineDoFinal(input, inputOffset, inputLen);
		}
		catch (IllegalBlockSizeException e) {
			return null;
		}
		catch (BadPaddingException e) {
			return null;
		}
	
	}

	/* (non-Javadoc)
	 * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
	 */
	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {
		// RSA is not a block cipher. This does exactly the same thing as engineDoFinal.
		// It is important to note that the only exception thrown from this method is
		// the short block exception, so it should be avoided.
		try {
			return engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
		}
		catch (IllegalBlockSizeException e) {
			return 0;
		}
		catch (BadPaddingException e) {
			return 0;
		}
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
				k = publicKey.bitsize / 8;
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
				privateKey = crt;
				privateKey.bitsize = n.bitLength();
				k = privateKey.bitsize / 8;
			}
			else if (key instanceof RSAPrivateKey) {
				RSA.ModulusPrivateKey mod = rsa.new ModulusPrivateKey();
				mod.n = ((RSAPrivateKey) key).getModulus();
				mod.d = ((RSAPrivateKey) key).getPrivateExponent();
				privateKey = mod;
				privateKey.bitsize = mod.n.bitLength();
				k = privateKey.bitsize / 8;
			}
			else {
				throw new InvalidKeyException("Not a valid RSA private key");
			}
			break;
		}

	}

}
