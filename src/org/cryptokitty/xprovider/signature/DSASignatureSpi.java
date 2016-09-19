/**
 * 
 */
package org.cryptokitty.xprovider.signature;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.cryptokitty.xprovider.EncodingException;
import org.cryptokitty.xprovider.random.BBSSecureRandom;
import org.cryptokitty.xprovider.x509.der.DERInteger;
import org.cryptokitty.xprovider.x509.der.DERSequence;
import org.cryptokitty.xprovider.x509.der.DERType;

/**
 * @author stevebrenneis
 *
 */
public class DSASignatureSpi extends SignatureSpi {

	/*
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/*
	 * DSA signer/verifier.
	 */
	private DSA dsa;

	/*
	 * Allowable key sizes.
	 */
	private boolean keysize1024;
	private boolean keysize2048;
	private boolean keysize3072;

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
	public DSASignatureSpi(String algorithm) {

		accumulator = new ByteArrayOutputStream();
		try {
			dsa = new DSA(algorithm, new BBSSecureRandom());
		}
		catch (NoSuchAlgorithmException e) {
			// Shouldn't happen.
			throw new RuntimeException(e);
		}

		switch(algorithm ) {
		case "SHA-1":
			keysize1024 = true;
			keysize2048 = false;
			keysize3072 = false;
			break;
		case "SHA-224":
			keysize1024 = false;
			keysize2048 = true;
			keysize3072 = false;
			break;
		case "SHA-256":
			keysize1024 = false;
			keysize2048 = true;
			keysize3072 = true;
			break;
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
			switch(this.publicKey.getParams().getP().bitLength()) {
			case 1024:
				if (!keysize1024) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			case 2048:
				if (!keysize2048) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			case 3072:
				if (!keysize3072) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			default:
				throw new InvalidKeyException("Invalid key size");
			}

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
			switch(this.privateKey.getParams().getP().bitLength()) {
			case 1024:
				if (!keysize1024) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			case 2048:
				if (!keysize2048) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			case 3072:
				if (!keysize3072) {
					throw new InvalidKeyException("Invalid key size");
				}
				break;
			default:
				throw new InvalidKeyException("Invalid key size");
			}

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
