/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.jni.BigInteger;
import org.cryptokitty.exceptions.SignatureException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.BadParameterException;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class RSAPrivateCrtKey extends RSAPrivateKey {

	/**
	 * Private exponent.
	 */
	private BigInteger d;

	/**
	 * Prime exponent p.
	 */
	private BigInteger dP;

	/**
	 * Prime exponent q.
	 */
	private BigInteger dQ;

	/**
	 * Modulus.
	 */
	private BigInteger n;

	/**
	 * Prime p.
	 */
	private BigInteger p;

	/**
	 * Prime q.
	 */
	private BigInteger q;

	/**
	 * CRT coefficient.
	 */
	private BigInteger qInv;

	/**
	 * 
	 * @param p Prime P.
	 * @param q Prime Q.
	 * @param d Private exponent.
	 * @param e Public exponent.
	 */
	public RSAPrivateCrtKey(BigInteger p, BigInteger q, BigInteger d, BigInteger e) {

		this.p = p;
		this.q = q;
		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		dP = e.modInverse(pp);
		dQ = e.modInverse(qq);
		qInv = q.modInverse(p);
		this.d = d;
		//this.e = e;

		n = p.multiply(q);
		bitsize = n.bitLength();

	}

	/**
	 * 
	 * @param p Prime P.
	 * @param q Prime Q.
	 * @param dP Prime exponent P.
	 * @param dQ Prime exponent Q.
	 * @param qInv CRT coefficient.
	 */
	public RSAPrivateCrtKey(BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ,
																			BigInteger qInv) {

		this.p = p;
		this.q = q;
		this.dP = dP;
		this.dQ = dQ;
		this.qInv = qInv;

		n = p.multiply(q);
		bitsize = n.bitLength();

	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getModulus() {
		// TODO Auto-generated method stub
		return n;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPrimeP() {
		// TODO Auto-generated method stub
		return p;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPrimeQ() {
		// TODO Auto-generated method stub
		return q;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPrimeExponentP() {
		// TODO Auto-generated method stub
		return dP;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPrimeExponentQ() {
		// TODO Auto-generated method stub
		return dQ;
	}

	/**
	 * @return the d
	 */
	public BigInteger getPrivateExponent() {
		return d;
	}

	/**
	 * 
	 * @return
	 */
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
	public BigInteger rsadp(BigInteger c) throws IllegalBlockSizeException {

		// We have to compute the modulus for the range check
		// BigInteger n = p.multiply(q);	Hnadled in the constructor.

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
	public BigInteger rsasp1(BigInteger m) throws SignatureException {

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

	/**
	 * @param d the d to set
	 */
	public void setPrivateExponent(BigInteger d) {
		this.d = d;
	}

}
