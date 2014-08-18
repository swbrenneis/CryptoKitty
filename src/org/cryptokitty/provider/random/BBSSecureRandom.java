/**
 * 
 */
package org.cryptokitty.provider.random;

import java.security.SecureRandom;

import org.cryptokitty.provider.CryptoKittyProvider;

/**
 * @author Steve Brenneis
 *
 * Wrapper class for the BBS secure random.
 * JCE doesn't let us use non-standard names.
 */
@SuppressWarnings("serial")
public class BBSSecureRandom extends SecureRandom {

	/**
	 * 
	 */
	public BBSSecureRandom() {
		super(new BBSSecureRandomSpi(), new CryptoKittyProvider());
	}

	/**
	 * @param seed
	 */
	public BBSSecureRandom(byte[] seed) {
		super(new BBSSecureRandomSpi(), new CryptoKittyProvider());
		setSeed(seed);
	}

}
