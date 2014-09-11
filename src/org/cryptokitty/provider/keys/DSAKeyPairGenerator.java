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

import org.cryptokitty.provider.BadParameterException;
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
		// In general, seedlen (third parameter), should equal N, but
		// should never be less than 160.
		DSAParameterGenerator gen = null;
		try {
			gen = new DSAParameterGenerator(L, N, N);
			gen.generateParameters(1);
		}
		catch (BadParameterException e) {
			// Shouldn't happen
			throw new RuntimeException(e);
		}
		BigInteger q = gen.getQ();
		BigInteger p = gen.getP();
		BigInteger pp = p.subtract(BigInteger.ONE);
		// p-1 must be a multiple of q. The prime generator should have
		// taken care of this, but just in case.
		while (!pp.mod(q).equals(BigInteger.ZERO)) {
			gen.generateParameters(1);
			q = gen.getQ();
			p = gen.getP();
		}

		BigInteger g = gen.getG();

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
