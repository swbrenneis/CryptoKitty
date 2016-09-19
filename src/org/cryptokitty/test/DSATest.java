/**
 * 
 */
package org.cryptokitty.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import org.cryptokitty.xprovider.CryptoKittyProvider;

/**
 * @author stevebrenneis
 *
 */
public class DSATest {

	/**
	 * 
	 */
	public DSATest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		String message = "The quick brown fox jumped over the lazy dog";

		Security.addProvider(new CryptoKittyProvider());

		try {

			// 1024 bit key - SHA-1
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "CryptoKitty");
			keyGen.initialize(1024);
			KeyPair pair = keyGen.generateKeyPair();

			Signature sign = Signature.getInstance("SHA1withDSA", "CryptoKitty");
			sign.initSign(pair.getPrivate());
			sign.update(message.getBytes("UTF-8"));
			byte[] signature = sign.sign();

			Signature verify = Signature.getInstance("SHA1withDSA", "CryptoKitty");
			verify.initVerify(pair.getPublic());
			verify.update(message.getBytes("UTF-8"));
			if (verify.verify(signature)) {
				System.out.println("DSA signature test 1 passed!");
			}
			else {
				System.out.println("DSA signature test 1 failed!");
			}

			// 2048 bit key - SHA-224
			keyGen = KeyPairGenerator.getInstance("DSA", "CryptoKitty");
			keyGen.initialize(2048);
			pair = keyGen.generateKeyPair();

			sign = Signature.getInstance("SHA224withDSA", "CryptoKitty");
			sign.initSign(pair.getPrivate());
			sign.update(message.getBytes("UTF-8"));
			signature = sign.sign();

			verify = Signature.getInstance("SHA224withDSA", "CryptoKitty");
			verify.initVerify(pair.getPublic());
			verify.update(message.getBytes("UTF-8"));
			if (verify.verify(signature)) {
				System.out.println("DSA signature test 2 passed!");
			}
			else {
				System.out.println("DSA signature test 2 failed!");
			}

			// 2048 bit key - SHA-256
			keyGen = KeyPairGenerator.getInstance("DSA", "CryptoKitty");
			keyGen.initialize(2048);
			pair = keyGen.generateKeyPair();

			sign = Signature.getInstance("SHA256withDSA", "CryptoKitty");
			sign.initSign(pair.getPrivate());
			sign.update(message.getBytes("UTF-8"));
			signature = sign.sign();

			verify = Signature.getInstance("SHA256withDSA", "CryptoKitty");
			verify.initVerify(pair.getPublic());
			verify.update(message.getBytes("UTF-8"));
			if (verify.verify(signature)) {
				System.out.println("DSA signature test 3 passed!");
			}
			else {
				System.out.println("DSA signature test 3 failed!");
			}

			// 3072 bit key - SHA-256
			keyGen = KeyPairGenerator.getInstance("DSA", "CryptoKitty");
			keyGen.initialize(3072);
			pair = keyGen.generateKeyPair();

			sign = Signature.getInstance("SHA256withDSA", "CryptoKitty");
			sign.initSign(pair.getPrivate());
			sign.update(message.getBytes("UTF-8"));
			signature = sign.sign();

			verify = Signature.getInstance("SHA256withDSA", "CryptoKitty");
			verify.initVerify(pair.getPublic());
			verify.update(message.getBytes("UTF-8"));
			if (verify.verify(signature)) {
				System.out.println("DSA signature test 4 passed!");
			}
			else {
				System.out.println("DSA signature test 4 failed!");
			}

		}
		catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			System.out.println("DSA signature test failed");
		}
		catch (NoSuchProviderException e) {
			System.err.println(e.getMessage());
			System.out.println("DSA signature test failed");
		}
		catch (SignatureException e) {
			System.err.println(e.getMessage());
			System.out.println("DSA signature test failed");
		}
		catch (UnsupportedEncodingException e) {
			System.err.println(e.getMessage());
			System.out.println("DSA signature test failed");
		}
		catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
			System.out.println("DSA signature test failed");
		}

	}

}
