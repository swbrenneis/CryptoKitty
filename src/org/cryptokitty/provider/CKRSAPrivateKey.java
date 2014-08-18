/**
 * 
 */
package org.cryptokitty.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

/**
 * @author stevebrenneis
 *
 */
public class CKRSAPrivateKey implements RSAPrivateKey {

	/*
	 * Private exponent.
	 */
	private BigInteger d;

	/*
	 * Modulus.
	 */
	private BigInteger n;

	/**
	 * 
	 */
	public CKRSAPrivateKey(BigInteger n, BigInteger d) {
		this.n = n;
		this.d = d;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return n;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateKey#getPrivateExponent()
	 */
	@Override
	public BigInteger getPrivateExponent() {
		// TODO Auto-generated method stub
		return d;
	}

}
