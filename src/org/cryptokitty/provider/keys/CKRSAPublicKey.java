/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author stevebrenneis
 *
 */
@SuppressWarnings("serial")
public class CKRSAPublicKey implements RSAPublicKey {

	/*
	 * Public exponent.
	 */
	private BigInteger e;

	/*
	 * Modulus.
	 */
	private BigInteger n;

	/**
	 * 
	 */
	public CKRSAPublicKey(BigInteger n, BigInteger e) {
		this.n = n;
		this.e = e;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return "RSA";
	}

	/*
	 * Return the key size.
	 */
	public int getBitsize() {
		return n.bitLength();
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAKey#getModulus()
	 */
	@Override
	public BigInteger getModulus() {
		return n;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPublicKey#getPublicExponent()
	 */
	@Override
	public BigInteger getPublicExponent() {
		return e;
	}

}
