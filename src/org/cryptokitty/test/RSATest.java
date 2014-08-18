/**
 * 
 */
package org.cryptokitty.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.cryptokitty.provider.CryptoKittyProvider;

/**
 * @author stevebrenneis
 *
 */
public class RSATest {

	/**
	 * 
	 */
	public RSATest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		Security.addProvider(new CryptoKittyProvider());

		// Generate a key pair.
		try {
			// Generate a key pair.
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "CryptoKitty");
			KeyPair pair = keyGen.generateKeyPair();

		}
		catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA Test 1 failed!");;
		}
		catch (NoSuchProviderException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA Test 1 failed!");;
		}
	}

}
