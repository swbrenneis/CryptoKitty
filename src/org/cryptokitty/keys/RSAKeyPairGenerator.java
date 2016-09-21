/**
 * 
 */
package org.cryptokitty.keys;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.cryptokitty.random.FortunaSecureRandom;

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
	private static final BigInteger THREE = BigInteger.valueOf(3L);

	/*
	 * Key size in bits.
	 */
	private int keysize;

	/*
	 * RNG for generating primes.
	 */
	private SecureRandom random;

	/**
	 * 
	 */
	public RSAKeyPairGenerator() {
		// Defaults keysize = 1024, random = BBS.
		keysize = 1024;
		random = new FortunaSecureRandom();
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

		// BigInteger e = BigInteger.valueOf(65537);

		BigInteger p = BigInteger.probablePrime(keysize / 2, random);
		BigInteger q = BigInteger.probablePrime(keysize / 2, random);
		// Get the modulus and make sure it is the right bit size.
		BigInteger n = p.multiply(q);
		while (n.bitLength() != keysize) {
			q = BigInteger.probablePrime(keysize / 2, random);
			n = p.multiply(q);
		}

		// Calculate phi(n) = (p - 1) * (q - 1)
		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		BigInteger phi = pp.multiply(qq);
		// Calculate the public exponent.
		// e is coprime (gcd = 1) with phi.
		boolean eFound = false;
		BigInteger e = null;
		BigInteger nn = n.subtract(BigInteger.ONE);
		while (!eFound) {
			e = BigInteger.probablePrime(64, random);
			// 3 < e <= n-1
			if (e.compareTo(THREE) > 0 && e.compareTo(nn) <= 0) {
				eFound = e.gcd(phi).equals(BigInteger.ONE);

			}
		}

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