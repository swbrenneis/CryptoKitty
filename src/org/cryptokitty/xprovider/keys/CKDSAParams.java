/**
 * 
 */
package org.cryptokitty.xprovider.keys;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

/**
 * @author Steve Brenneis
 *
 */
public class CKDSAParams implements DSAParams {

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

	/**
	 * 
	 */
	public CKDSAParams(BigInteger p, BigInteger q, BigInteger g) {
		this.p = p;
		this.q = q;
		this.g = g;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.DSAParams#getP()
	 */
	@Override
	public BigInteger getP() {
		return p;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.DSAParams#getQ()
	 */
	@Override
	public BigInteger getQ() {
		return q;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.DSAParams#getG()
	 */
	@Override
	public BigInteger getG() {
		return g;
	}

}
