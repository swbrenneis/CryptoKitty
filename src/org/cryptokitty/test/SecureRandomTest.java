/**
 * 
 */
package org.cryptokitty.test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.cryptokitty.provider.CryptoKittyProvider;

/**
 * @author stevebrenneis
 *
 */
public class SecureRandomTest {

	/**
	 * 
	 */
	public SecureRandomTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		Security.addProvider(new CryptoKittyProvider());

		try {
			SecureRandom random = SecureRandom.getInstance("BBS", "CryptoKitty");
			for (int i = 0; i < 100; i++) {
				System.out.println(String.valueOf(random.nextLong()));
			}
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println("Test 1 failed: " + e.getMessage());
		}
		catch (NoSuchProviderException e) {
			System.err.println("Test 1 failed: " + e.getMessage());
		}
		
	}

}
