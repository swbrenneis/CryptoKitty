/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.cipher.RSA;
import org.cryptokitty.provider.keys.CKRSAPrivateKey;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author Steve Brenneis
 *
 */
public class RSASignature extends SignatureSpi {

	/*
	 * Message buffer.
	 */
	private ByteArrayOutputStream buffer;

	/*
	 * The private key.
	 */
	private CKRSAPrivateKey privateKey;

	/*
	 * The private key.
	 */
	private CKRSAPublicKey publicKey;

	/*
	 * The signature implementation.
	 */
	private RSA rsa;

	/**
	 * 
	 */
	public RSASignature(RSA rsa) {
		privateKey = null;
		publicKey = null;
		this.rsa = rsa;
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineInitVerify(java.security.PublicKey)
	 */
	@Override
	protected void engineInitVerify(PublicKey publicKey)
			throws InvalidKeyException {

		if (publicKey instanceof CKRSAPublicKey) {
			this.publicKey = (CKRSAPublicKey)publicKey;
			// k = publicKey.bitsize / 8;
		}
		else {
			throw new InvalidKeyException("Not a valid RSA public key");
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineInitSign(java.security.PrivateKey)
	 */
	@Override
	protected void engineInitSign(PrivateKey privateKey)
			throws InvalidKeyException {

		if (privateKey instanceof CKRSAPrivateKey) {
			this.privateKey = (CKRSAPrivateKey)privateKey;
			// k = privateKey.bitsize / 8;
		}
		else {
			throw new InvalidKeyException("Not a valid RSA private key");
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineUpdate(byte)
	 */
	@Override
	protected void engineUpdate(byte b)
			throws java.security.SignatureException {
		buffer.write(b);
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws java.security.SignatureException {
		buffer.write(b, off, len);
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineSign()
	 */
	@Override
	protected byte[] engineSign()
			throws java.security.SignatureException {
		if (privateKey != null) {
			try {
				return rsa.sign(privateKey, buffer.toByteArray());
			}
			catch (ProviderException e) {
				throw new java.security.SignatureException(e);
			}
		}
		else {
			throw new IllegalStateException("Signature not initialized");
		}
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineVerify(byte[])
	 */
	@Override
	protected boolean engineVerify(byte[] sigBytes)
			throws java.security.SignatureException {
		if (publicKey != null) {
			return rsa.verify(publicKey, buffer.toByteArray(), sigBytes);
		}
		else {
			throw new IllegalStateException("Signature not initialized");
		}
	}

	/**
	 * 
	 * @see java.security.SignatureSpi#engineSetParameter(java.lang.String, java.lang.Object)
	 * @deprecated
	 */
	@Override
	protected void engineSetParameter(String param, Object value)
			throws InvalidParameterException {
		throw new InvalidParameterException("Method deprecated");
	}

	/**
	 * 
	 * @see java.security.SignatureSpi#engineGetParameter(java.lang.String)
	 * @deprecated
	 */
	@Override
	protected Object engineGetParameter(String param)
			throws InvalidParameterException {
		throw new InvalidParameterException("Method deprecated");
	}

	/*
	 * (non-Javadoc)
	 * @see java.security.SignatureSpi#engineGetParameters()
	 */
	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see java.security.SignatureSpi#engineSetParameter(java.security.spec.AlgorithmParameterSpec)
	 */
	@Override
	protected void engineSetParameter(AlgorithmParameterSpec params) {
		
	}

}
