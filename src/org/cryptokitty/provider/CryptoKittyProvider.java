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
		put("Cipher.CAST5 SupportedModes", "CFB|CFB8");
		put("Cipher.CAST5 SupportedPaddings", "NOPADDING");

		put("KeyGenerator.S2K", "org.cryptokitty.provider.S2KKeyGenerator");

		put("Cipher.RSA", "org.cryptokitty.provider.RSACipher");
		put("Cipher.RSA SupportedModes", "ECB");
		// Support all RSA v2.1 SHA hash algorithms. Does not support MD2 or MD5 hashes.
		put("Cipher.RSA SupportedPaddings", "PKCS1Padding|OAEPWithSHA-1AndMGF1Padding|"
				+ "OAEPWithSHA-256AndMGF1Padding|OAEPWithSHA-384AndMGF1Padding|"
				+ "OAEPWithSHA-512AndMGF1Padding");

		// Support all RSA v2.1 PSS SHA has algorithms. Does not support MD2 or MD5 hashes.
		// The hash algorithm will be passed in with the algorithm parameters along with
		// the selection of the EMSA encoding (PSS or PKCS1).
		put("Signature.SHA1withRSA", "org.cryptokitty.provider.RSASignature");
		put("Signature.SHA256withRSA", "org.cryptokitty.provider.RSASignature");
		put("Signature.SHA384withRSA", "org.cryptokitty.provider.RSASignature");
		put("Signature.SHA512withRSA", "org.cryptokitty.provider.RSASignature");

		put("KeyPairGenerator.RSA", "org.cryptokitty.provider.RSAKeyPairGenerator");
	}

}
