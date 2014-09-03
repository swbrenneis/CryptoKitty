/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKDSAPublicKey implements DSAPublicKey {

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
	 * Public key.
	 */
	private BigInteger y;

	/**
	 * 
	 */
	public CKDSAPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
		this.p = p;
		this.q = q;
		this.g = g;
		this.y = y;
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
		// TODO Auto-generated method stub
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
	 * @see java.security.interfaces.DSAPublicKey#getY()
	 */
	@Override
	public BigInteger getY() {
		return y;
	}

}
