/**
 * 
 */
package org.cryptokitty.keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.cryptokitty.jni.BigInteger;

/**
 * @author Steve Brenneis
 *
 * This class generates the CRT version of the private key by
 * default. The (n, d) version can be specified in the
 * algorithm parameters.
 */
public class RSAKeyPairGenerator {

	/*
	 * BigInteger constants.
	 */
	private static final BigInteger THREE = new BigInteger(3L);

	/*
	 * Key size in bits.
	 */
	private int keysize;

	/*
	 * RNG for generating primes.
	 */
	@SuppressWarnings("unused")
	private SecureRandom random;

	/**
	 * 
	 */
	public RSAKeyPairGenerator() {
		// Defaults keysize = 1024, random = BBS.
		keysize = 1024;

	}

	/**
	 * 
	 * @param keysize
	 * @param random
	 */
	public void initialize(int keysize, SecureRandom random) {

		this.keysize = keysize;
		this.random = random;

	}

	/**
	 * 
	 * @return
	 */
	public KeyPair generateKeyPair() {

		BigInteger e = new BigInteger(65537L);

		BigInteger p = BigInteger.probablePrime(keysize / 2);
		BigInteger q = BigInteger.probablePrime(keysize / 2);
		// Get the modulus and make sure it is the right bit size.
		BigInteger n = p.multiply(q);
		while (n.bitLength() != keysize) {
			p = BigInteger.probablePrime(keysize / 2);
			q = BigInteger.probablePrime(keysize / 2);
			n = p.multiply(q);
		}

		// Calculate phi(n) = (p - 1) * (q - 1)
		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		BigInteger phi = pp.multiply(qq);
		// Calculate the public exponent.
		// e is coprime (gcd = 1) with phi.
		//boolean eFound = false;
		//BigInteger e = null;
		//while (!eFound) {
		//	e = BigInteger.probablePrime(64);
			// 3 < e < n
		//	if (e.compareTo(THREE) > 0 && e.compareTo(n) < 0) {
		//		eFound = e.gcd(phi).equals(BigInteger.ONE);

		//	}
		//}

		// d * e = 1 mod phi
		BigInteger d = e.modInverse(phi);
		
		// Create the public key.
		PublicKey pub = new RSAPublicKey(n, e);
		// Create the private key.
		// TODO Option to generate modulus key.
		// PrivateKey prv = new CKRSAPrivateKey(n, d);
		PrivateKey prv = new RSAPrivateCrtKey(p, q, d, e);

		return new KeyPair(pub, prv);

	}

}
