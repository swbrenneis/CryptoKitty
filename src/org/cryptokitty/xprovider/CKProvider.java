/**
 * 
 */
package org.cryptokitty.xprovider;

import java.security.Provider;

/**
 * @author stevebrenneis
 *
 */
public class CKProvider extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8807503661268695070L;

	/**
	 * 
	 */
	private static double VERSION = 0.1;
	
	/**
	 * @param name
	 * @param version
	 * @param info
	 */
	public CKProvider() {
		super("CK", VERSION, "CryptoKitty Java strong encryption");

		put("MessageDigest.MD5", "org.cryptokitty.provider.digest.MD5Spi");
		put("MessageDigest.SHA-1", "org.cryptokitty.provider.digest.SHA1Spi");
		put("MessageDigest.SHA-224", "org.cryptokitty.provider.digest.SHA224Spi");
		put("MessageDigest.SHA-256", "org.cryptokitty.provider.digest.SHA256Spi");
		put("MessageDigest.SHA-384", "org.cryptokitty.provider.digest.SHA384Spi");
		put("MessageDigest.SHA-512", "org.cryptokitty.provider.digest.SHA512Spi");
		put("MessageDigest.RIPEMD-160", "org.cryptokitty.provider.digest.RIPEMD160Spi");
		put("Cipher.AES", "org.cryptokitty.provider.cipher.AESSpi");
		put("Cipher.AES//NoPadding", "org.cryptokitty.provider.cipher.AESSpi");
		put("Cipher.CAST5", "org.cryptokitty.provider.cipher.CAST5Spi");
		put("Cipher.CAST5//NoPadding", "org.cryptokitty.provider.cipher.CAST5Spi");
		put("Cipher.AES/CFB/NoPadding", "org.cryptokitty.provider.cipher.AESCFBSpi");
		put("Cipher.AES/GCM/NoPadding", "org.cryptokitty.provider.cipher.AESGCMSpi");
		put("Cipher.RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
										"org.cryptokitty.provider.cipher.OAEPSHA1Spi");
		put("Cipher.RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
										"org.cryptokitty.provider.cipher.OAEPSHA256Spi");
		put("KeyPairGenerator.RSA", "org.cryptokitty.provider.keys.RSAKeyPairGeneratorSpi");

	}

}
