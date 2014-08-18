/**
 * 
 */
package org.cryptokitty.provider;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

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
	private RSA.PrivateKey privateKey;

	/*
	 * The private key.
	 */
	private RSA.PublicKey publicKey;

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

		if (publicKey instanceof RSAPublicKey) {
			this.publicKey = rsa.new PublicKey();
			this.publicKey.n = ((RSAPublicKey) publicKey).getModulus();
			this.publicKey.e = ((RSAPublicKey) publicKey).getPublicExponent();
			this.publicKey.bitsize = this.publicKey.n.bitLength();
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

		if (privateKey instanceof RSAPrivateCrtKey) {
			RSA.CRTPrivateKey crt = rsa.new CRTPrivateKey();
			crt.p = ((RSAPrivateCrtKey) privateKey).getPrimeP();
			crt.q = ((RSAPrivateCrtKey) privateKey).getPrimeQ();
			crt.dP = ((RSAPrivateCrtKey) privateKey).getPrimeExponentP();
			crt.dQ = ((RSAPrivateCrtKey) privateKey).getPrimeExponentQ();
			crt.qInv = ((RSAPrivateCrtKey) privateKey).getCrtCoefficient();
			BigInteger n = crt.p.multiply(crt.q);
			this.privateKey.bitsize = n.bitLength();
			this.privateKey = crt;
			// k = privateKey.bitsize / 8;
		}
		else if (privateKey instanceof RSAPrivateKey) {
			RSA.ModulusPrivateKey mod = rsa.new ModulusPrivateKey();
			mod.n = ((RSAPrivateKey) privateKey).getModulus();
			mod.d = ((RSAPrivateKey) privateKey).getPrivateExponent();
			this.privateKey.bitsize = mod.n.bitLength();
			this.privateKey = mod;
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
