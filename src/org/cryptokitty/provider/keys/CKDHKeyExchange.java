/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author stevebrenneis
 *
 */
public class CKDHKeyExchange {

	/**
	 * Modulus bit size.
	 */
	private int bitsize;

	/**
	 * Generator
	 */
	private BigInteger g;

	/**
	 * Prime modulus
	 */
	private BigInteger p;

	/**
	 * Private key.
	 */
	private BigInteger a;

	/**
	 * Secret, pk^a mod p, pk = foreign public key
	 */
	private BigInteger s;

	/**
	 * DH public key, g^a mod p
	 */
	private BigInteger publicKey;

    /**
	 * 
	 */
	public CKDHKeyExchange() {
		
		bitsize = 2048;
		g = BigInteger.ZERO;
		p = BigInteger.ZERO;
		a = BigInteger.ZERO;
		s = BigInteger.ZERO;
		publicKey = BigInteger.ZERO;

	}

	/**
	 * 
	 * @return
	 */
	public BigInteger generatePublicKey() {

		// TODO FortunaSecureRandom rnd;
		SecureRandom rnd;
		try {
			rnd = SecureRandom.getInstanceStrong();
		}
		catch (NoSuchAlgorithmException e) {
			// Hope not
			return BigInteger.ZERO;
		}

	    if (p == BigInteger.ZERO) {
	        p = BigInteger.probablePrime(bitsize, rnd);
	        while (p.bitLength() < bitsize) {
	            p = BigInteger.probablePrime(bitsize, rnd);
	        }
	        g = BigInteger.probablePrime(bitsize/2, rnd);
	        while (g.bitLength() < bitsize/2) {
	            g = BigInteger.probablePrime(bitsize/2, rnd);
	        }
	    }

	    if (a == BigInteger.ZERO) {
	        a = BigInteger.probablePrime(bitsize/4, rnd);
	    }

	    publicKey = g.modPow(a, p);

	    return publicKey;

	}

	/*
	 * Return the generator. Will be ZERO if not explicitly set or if
	 * the public key has not been generated.
	 */
	BigInteger getGenerator() {

	    return g;

	}

	/*
	 * Return the modulus. Will be ZERO if not explicitly set or if
	 * the public key has not been generated.
	 */
	BigInteger getModulus() {

	    return p;

	}

	/*
	 * Return the D-H public key. Will be ZERO if not explicitly set or if
	 * the public key has not been generated.
	 */
	BigInteger getPublicKey() {

	    return publicKey;

	}

	/*
	 * Generate and return the D-H public key.
	 */
	BigInteger getSecret(BigInteger fpk) {

	    if (a == BigInteger.ZERO) {
	    	SecureRandom rnd;
	    	try {
				rnd = SecureRandom.getInstanceStrong();
			}
	    	catch (NoSuchAlgorithmException e) {
				// Hope not
				return BigInteger.ZERO;
			}
	        //FortunaSecureRandom rnd;
	        a = BigInteger.probablePrime(bitsize/4, rnd);
	    }

	    s = fpk.modPow(a, p);
	    return s;

	}

	/*
	 * Return the D-H public key. Will be ZERO if if hasn't been
	 * generated with the foreign public key.
	 */
	BigInteger getSecret() {

	    return s;

	}

	void setBitsize(int b) {

	    bitsize = b;

	}

	void setGenerator(BigInteger gen) {

	    g = gen;

	}

	void setModulus(BigInteger mod) {

	    p = mod;

	}

}
