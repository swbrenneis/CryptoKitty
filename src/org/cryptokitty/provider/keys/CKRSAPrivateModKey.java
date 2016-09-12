/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.provider.BadParameterException;

/**
 * @author stevebrenneis
 *
 */
public class CKRSAPrivateModKey extends CKRSAPrivateKey implements
		RSAPrivateKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6915387349637434980L;

	/*
	 * The modulus.
	 */
	BigInteger n;
	
	/*
	 * The private exponent.
	 */
	 BigInteger d;
	 
	/**
	 * @param n
	 * @param d
	 */
	public CKRSAPrivateModKey(BigInteger n, BigInteger d) {
		this.n = n;
		this.d = d;
		bitsize = n.bitLength();
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
	 * @see java.security.interfaces.RSAPrivateKey#getPrivateExponent()
	 */
	@Override
	public BigInteger getPrivateExponent() {
		// TODO Auto-generated method stub
		return d;
	}

	/**
	 * RSA decryption primitive, modulus and exponent
	 */
	public BigInteger rsadp(BigInteger c)
							throws IllegalBlockSizeException {

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new IllegalBlockSizeException("Illegal block zise");
		}

		// 2. Let m = c^d mod n.
		BigInteger m = c.modPow(d, n);

		return m;

	}

	/**
	 * Signature generation primitive. Modulus and exponent method.
	 * 
	 * @param K - Private key of the form (n, d).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	public BigInteger rsasp1(BigInteger m)
						throws SignatureException {

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 0 
				|| m.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new SignatureException("Invalid signature");
		}

		// Let s = m^d mod n.
		BigInteger s = m.modPow(d, n);

		return s;

	}

}
