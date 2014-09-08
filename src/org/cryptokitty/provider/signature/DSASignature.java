/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.random.BBSSecureRandom;
import org.cryptokitty.provider.x509.der.DERInteger;
import org.cryptokitty.provider.x509.der.DERSequence;
import org.cryptokitty.provider.x509.der.DERType;
import org.cryptokitty.provider.x509.der.EncodingException;

/**
 * @author stevebrenneis
 *
 */
public class DSASignature extends SignatureSpi {

	/*
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/*
	 * DSA signer/verifier.
	 */
	private DSA dsa;

	/*
	 * The private key.
	 */
	private DSAPrivateKey privateKey;

	/*
	 * The public key.
	 */
	private DSAPublicKey publicKey;

	/**
	 * 
	 */
	public DSASignature(String algorithm) {

		accumulator = new ByteArrayOutputStream();
		try {
			dsa = new DSA(algorithm, new BBSSecureRandom());
		}
		catch (UnsupportedAlgorithmException e) {
			// Shouldn't happen.
			throw new RuntimeException(e);
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineInitVerify(java.security.PublicKey)
	 */
	@Override
	protected void engineInitVerify(PublicKey publicKey)
			throws InvalidKeyException {

		if (publicKey instanceof DSAPublicKey) {
			this.publicKey = (DSAPublicKey)publicKey;
		}
		else {
			throw new InvalidKeyException("Not a DSA public key");
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineInitSign(java.security.PrivateKey)
	 */
	@Override
	protected void engineInitSign(PrivateKey privateKey)
			throws InvalidKeyException {

		if (privateKey instanceof DSAPrivateKey) {
			this.privateKey = (DSAPrivateKey)privateKey;
		}
		else {
			throw new InvalidKeyException("Not a DSA private key");
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineUpdate(byte)
	 */
	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		accumulator.write(b);
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws SignatureException {
		accumulator.write(b, off, len);
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineSign()
	 */
	@Override
	protected byte[] engineSign() throws SignatureException {

		// This will return an x.509 DER encoded signature.
		BigInteger[] rs = dsa.sign(privateKey, accumulator.toByteArray());
		DERSequence seq = new DERSequence();
		seq.add(new DERInteger(rs[0]));
		seq.add(new DERInteger(rs[1]));
		try {
			return seq.encode();
		}
		catch (EncodingException e) {
			throw new SignatureException("DER encoding error: "
													+ e.getMessage());
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineVerify(byte[])
	 */
	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {

		// Expects an x.509 DER encoded signature.
		DERSequence seq = new DERSequence();
		try {
			seq.decode(sigBytes);
		}
		catch (EncodingException e) {
			// Fail silently
			return false;
		}
		DERType[] rsder = seq.getElements();
		BigInteger r = ((DERInteger)rsder[0]).getValue();
		BigInteger s = ((DERInteger)rsder[1]).getValue();
		BigInteger[] rs = { r, s };

		return dsa.verify(publicKey, accumulator.toByteArray(),	rs);

	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineSetParameter(java.lang.String, java.lang.Object)
	 */
	@Override
	protected void engineSetParameter(String param, Object value)
			throws InvalidParameterException {
		// Unused.
	}

	/* (non-Javadoc)
	 * @see java.security.SignatureSpi#engineGetParameter(java.lang.String)
	 */
	@Override
	protected Object engineGetParameter(String param)
			throws InvalidParameterException {
		// Unused.
		return null;
	}

}
