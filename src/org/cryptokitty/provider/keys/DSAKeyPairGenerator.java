/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.cryptokitty.provider.random.BBSSecureRandom;

/**
 * @author Steve Brenneis
 *
 */
public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {

	/*
	 * Key size.
	 */
	private int L;

	/*
	 * Hash size.
	 */
	private int N;

	/*
	 * Secure PRNG
	 */
	private SecureRandom random;

	/**
	 * 
	 */
	public DSAKeyPairGenerator() {
		L = 1024;
		N = 160;
		random = new BBSSecureRandom();
	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#initialize(int, java.security.SecureRandom)
	 */
	@Override
	public void initialize(int keysize, SecureRandom random) {

		L = keysize;
		switch(L) {
		case 1024:
			N = 160;
			break;
		case 2048:
		case 3072:
			N = 256;
			break;
		default:
			throw new IllegalStateException("Illegal key size");
		}

		if (random == null) {
			random = new BBSSecureRandom();
		}
		else {
			this.random = random;
		}

	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#generateKeyPair()
	 */
	@Override
	public KeyPair generateKeyPair() {

		// Generate parameters
		BigInteger q = BigInteger.probablePrime(N, random);
		BigInteger p = BigInteger.probablePrime(L, random);
		BigInteger pp = p.subtract(BigInteger.ONE);
		// p-1 must be a multiple of q
		while (!q.divide(pp).equals(BigInteger.ZERO)) {
			p = BigInteger.probablePrime(L, random);
			pp = p.subtract(BigInteger.ONE);
		}
		// g = h**(p-1/q) mod p
		BigInteger h = new BigInteger(8, random);
		BigInteger g = h.modPow(pp.divide(q), p);
		while (g.equals(BigInteger.ONE)) {
			h = new BigInteger(8, random);
			g = h.modPow(pp.divide(q), p);
		}

		// 0 < x < p-1
		BigInteger x = new BigInteger(L-1, random);
		if (x.equals(BigInteger.ZERO)) {
			x = new BigInteger(L-1, random);
		}
		// y = g**x mod p
		BigInteger y = g.modPow(x, p);

		PublicKey pub = new CKDSAPublicKey(p, q, g, y);
		PrivateKey prv = new CKDSAPrivateKey(p, q, g, x);

		return new KeyPair(pub, prv);

	}

}
