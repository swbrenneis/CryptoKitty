/**
 * 
 */
package org.cryptokitty.keys;

import org.cryptokitty.jni.BigInteger;
import org.cryptokitty.random.FortunaSecureRandom;

/**
 * @author stevebrenneis
 *
 */
public class DHKeyExchange {

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
	public DHKeyExchange() {
		
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

		FortunaSecureRandom rnd = new FortunaSecureRandom();
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
	public BigInteger getGenerator() {

	    return g;

	}

	/*
	 * Return the modulus. Will be ZERO if not explicitly set or if
	 * the public key has not been generated.
	 */
	public BigInteger getModulus() {

	    return p;

	}

	/*
	 * Return the D-H public key. Will be ZERO if not explicitly set or if
	 * the public key has not been generated.
	 */
	public BigInteger getPublicKey() {

	    return publicKey;

	}

	/*
	 * Generate and return the D-H public key.
	 */
	public BigInteger getSecret(BigInteger fpk) {

	    if (a == BigInteger.ZERO) {
	    	FortunaSecureRandom rnd = new FortunaSecureRandom();
	        a = BigInteger.probablePrime(bitsize/4, rnd);
	    }

	    s = fpk.modPow(a, p);
	    return s;

	}

	/*
	 * Return the D-H public key. Will be ZERO if if hasn't been
	 * generated with the foreign public key.
	 */
	public BigInteger getSecret() {

	    return s;

	}

	public void setBitsize(int b) {

	    bitsize = b;

	}

	public void setGenerator(BigInteger gen) {

	    g = gen;

	}

	public void setModulus(BigInteger mod) {

	    p = mod;

	}

}
