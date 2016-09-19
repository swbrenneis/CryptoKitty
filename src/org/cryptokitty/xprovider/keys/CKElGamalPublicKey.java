/**
 * 
 */
package org.cryptokitty.xprovider.keys;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKElGamalPublicKey implements PublicKey {

	/*
	 * Modulus factor b.
	 */
	private BigInteger b;

	/*
	 * Generator factor g.
	 */
	private BigInteger g;

	/*
	 * Prime factor p.
	 */
	private BigInteger p;

	/**
	 * 
	 */
	public CKElGamalPublicKey(BigInteger p, BigInteger g, BigInteger b) {
		this.p = p;
		this.g = g;
		this.b = b;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "ElGamal";
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

	/*
	 * Get the modulus factor.
	 */
	public BigInteger getB() {
		return b;
	}

	/*
	 * Get the generator factor.
	 */
	public BigInteger getG() {
		return g;
	}

	/*
	 * Get the prime factor.
	 */
	public BigInteger getP() {
		return p;
	}

}
