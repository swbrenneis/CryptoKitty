/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

/**
 * @author Steve Brenneis
 *
 */
public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {

	/*
	 * Key size.
	 */
	private int L;

	/**
	 * 
	 */
	public DSAKeyPairGenerator() {
		L = 0;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#initialize(int, java.security.SecureRandom)
	 */
	@Override
	public void initialize(int keysize, SecureRandom random) {
		L = keysize;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyPairGeneratorSpi#generateKeyPair()
	 */
	@Override
	public KeyPair generateKeyPair() {

		int N;
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

		BigInteger g;
		BigInteger p;
		BigInteger q;

		return null;
	}

}
