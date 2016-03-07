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
 * @author stevebrenneis
 *
 */
public class ElGamalKeyPairGenerator extends KeyPairGeneratorSpi {

	/*
	 * Private key bitsize.
	 */
	private static final int PRIVATE_KEYSIZE = 64;

	/*
	 * Key size in bits.
	 */
	private int keysize;

	/*
	 * Secure PRNG.
	 */
	private SecureRandom random;

	/**
	 * 
	 */
	public ElGamalKeyPairGenerator() {

		keysize = 1024;
		random = new BBSSecureRandom();

	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#initialize(int, java.security.SecureRandom)
	 */
	@Override
	public void initialize(int keysize, SecureRandom random) {

		this.keysize = keysize;
		this.random = random;

	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#generateKeyPair()
	 */
	@Override
	public KeyPair generateKeyPair() {

		BigInteger p = BigInteger.probablePrime(keysize, random);
		BigInteger g = new BigInteger(keysize, random).mod(p);
		while (g.compareTo(BigInteger.ONE) <= 0) {
			g = new BigInteger(keysize, random).mod(p);
		}
		BigInteger x = new BigInteger(PRIVATE_KEYSIZE, random);
		BigInteger b = g.modPow(x, p);
		PublicKey publicKey = new CKElGamalPublicKey(p, g, b);
		PrivateKey privateKey = new CKElGamalPrivateKey(x);

		return new KeyPair(publicKey, privateKey);

	}

}
