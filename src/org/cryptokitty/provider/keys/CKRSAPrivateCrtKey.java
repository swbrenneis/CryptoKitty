/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;

import javax.crypto.IllegalBlockSizeException;

import org.cryptokitty.provider.BadParameterException;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CKRSAPrivateCrtKey extends CKRSAPrivateKey implements RSAPrivateCrtKey {

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
		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		dP = e.modInverse(pp);
		dQ = e.modInverse(qq);
		qInv = q.modInverse(p);
		this.d = d;
		this.e = e;
		
		n = p.multiply(q);
		bitsize = n.bitLength();
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
	
	/**
	 * RSA decryption primitive, CRT method
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param c - Ciphertext representative.
	 * 
	 * @return The plaintext representative
	 * 
	 * @throws BadParameterException if ciphertext representative is out of range
	 */
	public BigInteger rsadp(BigInteger c)
						throws IllegalBlockSizeException {

		// We have to compute the modulus for the range check
		BigInteger n = p.multiply(q);

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new IllegalBlockSizeException("Illegal block size");
		}

		// i.    Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
		BigInteger m_1 = c.modPow(dP, p);
		BigInteger m_2 = c.modPow(dQ, q);

		// iii.  Let h = (m_1 - m_2) * qInv mod p.
		BigInteger h = m_1.subtract(m_2).multiply(qInv).mod(p);

		// iv.   Let m = m_2 + q * h.
		BigInteger m = q.multiply(h).add(m_2);

		return m;

	}

	/**
	 * Signature generation primitive. CRT method.
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	public BigInteger rsasp1(BigInteger m)
						throws SignatureException {

		// We have to compute the modulus for the range check
		BigInteger n = p.multiply(q);

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 0 
				|| m.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new SignatureException("Invalid signature");
		}

		// i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
		BigInteger s_1 = m.modPow(dP, p);
		BigInteger s_2 = m.modPow(dQ, q);

		// iii.  Let h = (s_1 - s_2) * qInv mod p.
		BigInteger h = s_1.subtract(s_2).multiply(qInv).mod(p);

		// iv.   Let s = s_2 + q * h.
		BigInteger s = q.multiply(h).add(s_2);

		return s;

	}

}
