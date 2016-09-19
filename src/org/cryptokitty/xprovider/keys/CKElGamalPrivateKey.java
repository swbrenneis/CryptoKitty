/**
 * 
 */
package org.cryptokitty.xprovider.keys;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKElGamalPrivateKey implements PrivateKey {

	/*
	 * The private key.
	 */
	private BigInteger x;

	/**
	 * 
	 */
	public CKElGamalPrivateKey(BigInteger x) {
		this.x = x;
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
	 * Get the private key.
	 */
	public BigInteger getX() {
		return x;
	}

}
