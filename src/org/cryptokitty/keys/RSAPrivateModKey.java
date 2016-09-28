/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.jni.BigInteger;
import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.SignatureException;

/**
 * @author stevebrenneis
 *
 */
public class RSAPrivateModKey extends RSAPrivateKey {

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
	public RSAPrivateModKey(BigInteger n, BigInteger d) {
		this.n = n;
		this.d = d;
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
	public BigInteger rsasp1(BigInteger m) throws SignatureException {

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
