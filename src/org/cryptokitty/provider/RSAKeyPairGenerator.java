/**
 * 
 */
package org.cryptokitty.provider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.cryptokitty.provider.keys.CKRSAPrivateKey;
import org.cryptokitty.provider.keys.CKRSAPublicKey;

/**
 * @author Steve Brenneis
 *
 * This class generates the CRT version of the private key by
 * default. The (n, d) version can be specified in the
 * algorithm parameters.
 */
public class RSAKeyPairGenerator extends KeyPairGeneratorSpi {

	/*
	 * BigInteger constants.
	 */
	private static final BigInteger TWO = BigInteger.valueOf(2L);

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
		// Defaults, keysize = 1024, random = BBS.
		keysize = 1024;
		try {
			random = SecureRandom.getInstance("BBS", "CryptoKitty");
		}
		catch (NoSuchAlgorithmException e) {
			// Provider hasn't been set up yet. It would be a strange
			// circumstance, but it could happen.
			throw new IllegalStateException("CryptoKitty provider not initialized");
		}
		catch (NoSuchProviderException e) {
			// Provider hasn't been set up yet. It would be a strange
			// circumstance, but it could happen.
			throw new IllegalStateException("CryptoKitty provider not initialized");
		}

	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#initialize(int, java.security.SecureRandom)
	 */
	@Override
	public void initialize(int keysize, SecureRandom random) {
		// Hopefully, SecureRandom is a CryptoKitty implementation.
		// TODO Check?
		this.keysize = keysize;
		this.random = random;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#generateKeyPair()
	 */
	@Override
	public KeyPair generateKeyPair() {

		// Generate the modulus.
		BigInteger p = new BigInteger(keysize / 2, 100, random);
		BigInteger q = new BigInteger(keysize / 2, 100, random);
		BigInteger n = p.multiply(q);
		while (n.bitLength() != keysize) {
			n = p.multiply(q);
		}

		// Generate the public exponent.
		// BigInteger x = p.add(q).subtract(BigInteger.ONE);
		// BigInteger phi = n.add(x);
		// Calculate lambda(n) : LCM(p-1, q-1)
		BigInteger pp = q.subtract(BigInteger.ONE);
		BigInteger qq = q.subtract(BigInteger.ONE);
		BigInteger gcd = pp.gcd(qq);	// I could string this together but it would be a mess.
		BigInteger lambdaN = qq.divide(gcd).multiply(pp);

		// Calculate the public exponent. We'll use 2^16 + 1 for the size.
		BigInteger e = new BigInteger(16, 100, random).add(BigInteger.ONE);
		// This might take a while.
		while (e.gcd(lambdaN).compareTo(BigInteger.ONE) != 0) {
			e = new BigInteger(16, 100, random).add(BigInteger.ONE);
		}
		// Create the public key.
		PublicKey pub = new CKRSAPublicKey(n, e);

		// Calculate the private exponent.
		BigInteger d = new BigInteger(16, 100, random).add(BigInteger.ONE);
		while (d.multiply(e).mod(lambdaN).compareTo(BigInteger.ONE) != 0) {
			d = new BigInteger(16, 100, random).add(BigInteger.ONE);
		}
	
		PrivateKey prv = new CKRSAPrivateKey(n, d);
		
		return new KeyPair(pub, prv);

	}

}
