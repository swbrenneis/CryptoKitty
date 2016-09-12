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

import org.cryptokitty.provider.keys.CKRSAPrivateKey;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author Steve Brenneis
 *
 */
public class RSASignatureSpi extends SignatureSpi {

	/*
	 * Message buffer.
	 */
	protected ByteArrayOutputStream buffer;

	/*
	 * The private key.
	 */
	protected CKRSAPrivateKey privateKey;

	/*
	 * The private key.
	 */
	protected CKRSAPublicKey publicKey;

	/*
	 * The signature implementation.
	 */
	protected RSASignature rsa;

	/**
	 * 
	 */
	public RSASignatureSpi() {
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

		return rsa.sign(privateKey, buffer.toByteArray());

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineVerify(byte[])
	 */
	@Override
	protected boolean engineVerify(byte[] sigBytes)
			throws java.security.SignatureException {

		return rsa.verify(publicKey, buffer.toByteArray(), sigBytes);

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
