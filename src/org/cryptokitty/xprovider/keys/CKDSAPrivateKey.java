/**
 * 
 */
package org.cryptokitty.xprovider.keys;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKDSAPrivateKey implements DSAPrivateKey {

	/*
	 * Base.
	 */
	private BigInteger g;
	
	/*
	 * L-size prime.
	 */
	private BigInteger p;

	/*
	 * N-size prime.
	 */
	private BigInteger q;

	/*
	 * Private key.
	 */
	private BigInteger x;

	/**
	 * 
	 */
	public CKDSAPrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
		this.p = p;
		this.q = q;
		this.g = g;
		this.x = x;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.DSAKey#getParams()
	 */
	@Override
	public DSAParams getParams() {
		return new CKDSAParams(p, q, g);
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "DSA";
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
	 * @see java.security.interfaces.DSAPrivateKey#getX()
	 */
	@Override
	public BigInteger getX() {
		return x;
	}

}
