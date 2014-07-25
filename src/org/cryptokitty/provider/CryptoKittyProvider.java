/**
 * 
 */
package org.cryptokitty.provider;

import java.security.Provider;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CryptoKittyProvider extends Provider {

	/*
	 * Provider information.
	 */
	private static final String INFO = "CryptoKitty Provider v0.1";

	/**
	 * 
	 */
	public CryptoKittyProvider() {
		super("CryptoKitty", 0.1, INFO);

		put("Cipher.CAST5", "org.cryptokitty.provider.CAST5Cipher");
		put("Cipher.CAST5 SupportedModes", "CFB");
		put("Cipher.CAST5 SupportedPaddings", "NOPADDING");

		put("KeyGenerator.S2K", "org.cryptokitty.provider.S2KKeyGenerator");

	}

}
