/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.jni.BigInteger;
import java.security.PublicKey;

/**
 * @author stevebrenneis
 *
 * This implements the Java PublicKey interface purely so that it
 * can be used with the Java KeyPair class;
 */
@SuppressWarnings("serial")
public class RSAPublicKey implements PublicKey{

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
	public RSAPublicKey(BigInteger n, BigInteger e) {
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

	/**
	 * 
	 * @return
	 */
	public BigInteger getModulus() {
		return n;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPublicExponent() {
		return e;
	}

}
