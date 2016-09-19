/**
 * 
 */
package org.cryptokitty.xprovider;

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

		put("Cipher.CAST5", "org.cryptokitty.provider.cipher.CAST5Cipher");
		put("Cipher.CAST5 SupportedModes", "CFB|CFB8");
		put("Cipher.CAST5 SupportedPaddings", "NOPADDING");

		put("KeyGenerator.S2K", "org.cryptokitty.provider.keys.S2KKeyGenerator");

		put("Cipher.RSA", "org.cryptokitty.provider.cipher.RSACipher");
		put("Cipher.RSA SupportedModes", "ECB");
		// Support all RSA v2.1 SHA hash algorithms. Does not support MD2 or MD5 hashes.
		put("Cipher.RSA SupportedPaddings", "PKCS1Padding|OAEPWithSHA-1AndMGF1Padding|"
				+ "OAEPWithSHA-256AndMGF1Padding|OAEPWithSHA-384AndMGF1Padding|"
				+ "OAEPWithSHA-512AndMGF1Padding");

		// Support all RSA v2.1 PSS SHA hash algorithms. Does not support MD2 or MD5 hashes.
		// The hash algorithm will be passed in with the algorithm parameters along with
		// the selection of the EMSA encoding (PSS or PKCS1).
		put("Signature.SHA1withRSA", "org.cryptokitty.provider.signature.SHA1RSASignature");
		put("Signature.SHA256withRSA", "org.cryptokitty.provider.signature.SHA256RSASignature");
		put("Signature.SHA384withRSA", "org.cryptokitty.provider.signature.SHA384RSASignature");
		put("Signature.SHA512withRSA", "org.cryptokitty.provider.signature.SHA512RSASignature");
		put("Signature.SHA256withRSAPKCS1", "org.cryptokitty.provider.signature.SHA256PKCSRSASignature");

		put("KeyPairGenerator.RSA", "org.cryptokitty.provider.keys.RSAKeyPairGenerator");

		put("Signature.SHA1withDSA", "org.cryptokitty.provider.signature.SHA1DSASignature");
		put("Signature.SHA224withDSA", "org.cryptokitty.provider.signature.SHA224DSASignature");
		put("Signature.SHA256withDSA", "org.cryptokitty.provider.signature.SHA256DSASignature");

		put("KeyPairGenerator.DSA", "org.cryptokitty.provider.keys.DSAKeyPairGenerator");

		put("MessageDigest.MD5", "org.cryptokitty.provider.digest.MD5Spi");
		put("MessageDigest.SHA-1", "org.cryptokitty.provider.digest.SHA1Spi");
		put("MessageDigest.SHA-256", "org.cryptokitty.provider.digest.SHA256Spi");
		put("MessageDigest.SHA-384", "org.cryptokitty.provider.digest.SHA384Spi");
		put("MessageDigest.SHA-512", "org.cryptokitty.provider.digest.SHA512Spi");

	}

}
