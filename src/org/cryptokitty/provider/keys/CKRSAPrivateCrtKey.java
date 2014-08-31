/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKRSAPrivateCrtKey implements RSAPrivateCrtKey {

	/*
	 * Private exponent.
	 */
	private BigInteger d;

	/*
	 * Prime exponent p.
	 */
	private BigInteger dP;

	/*
	 * Prime exponent q.
	 */
	private BigInteger dQ;

	/*
	 * Public exponent.
	 */
	private BigInteger e;

	/*
	 * Modulus.
	 */
	private BigInteger n;

	/*
	 * Prime p.
	 */
	private BigInteger p;

	/*
	 * Prime q.
	 */
	private BigInteger q;

	/*
	 * CRT coefficient.
	 */
	private BigInteger qInv;

	/**
	 * 
	 */
	public CKRSAPrivateCrtKey(BigInteger p, BigInteger q, BigInteger d, BigInteger e) {
		this.p = p;
		this.q = q;
		n = p.multiply(q);
		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		dP = e.modInverse(pp);
		dQ = e.modInverse(qq);
		qInv = q.modInverse(p);
		this.d = d;
		this.e = e;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateKey#getPrivateExponent()
	 */
	@Override
	public BigInteger getPrivateExponent() {
		// TODO Auto-generated method stub
		return d;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return "RSA";
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
	 * @see java.security.interfaces.RSAPrivateCrtKey#getPublicExponent()
	 */
	@Override
	public BigInteger getPublicExponent() {
		// TODO Auto-generated method stub
		return e;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateCrtKey#getPrimeP()
	 */
	@Override
	public BigInteger getPrimeP() {
		// TODO Auto-generated method stub
		return p;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateCrtKey#getPrimeQ()
	 */
	@Override
	public BigInteger getPrimeQ() {
		// TODO Auto-generated method stub
		return q;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateCrtKey#getPrimeExponentP()
	 */
	@Override
	public BigInteger getPrimeExponentP() {
		// TODO Auto-generated method stub
		return dP;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateCrtKey#getPrimeExponentQ()
	 */
	@Override
	public BigInteger getPrimeExponentQ() {
		// TODO Auto-generated method stub
		return dQ;
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPrivateCrtKey#getCrtCoefficient()
	 */
	@Override
	public BigInteger getCrtCoefficient() {
		// TODO Auto-generated method stub
		return qInv;
	}

}
