/**
 * 
 */
package org.cryptokitty.random;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

/**
 * @author stevebrenneis
 *
 * This class provides an adapter between the CryptoKitty SecureRandom interface
 * and the Java SecureRandom abstraction. It is used so that the CryptoKitty
 * secure RNGs can be used with the BigInteger class.
 */
public abstract class SecureRandomWrapper extends SecureRandom {

	/**
	 * 
	 */
	public SecureRandomWrapper() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param seed
	 */
	public SecureRandomWrapper(byte[] seed) {
		super(seed);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param secureRandomSpi
	 * @param provider
	 */
	public SecureRandomWrapper(SecureRandomSpi secureRandomSpi, Provider provider) {
		super(secureRandomSpi, provider);
		// TODO Auto-generated constructor stub
	}

}
