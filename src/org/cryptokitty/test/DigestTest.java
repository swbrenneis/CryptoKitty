/**
 * 
 */
package org.cryptokitty.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.cryptokitty.provider.digest.CKSHA256;

/**
 * @author stevebrenneis
 *
 */
public class DigestTest {

	/**
	 * 
	 */
	public DigestTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		byte[] message = 
			{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
				0x21
			};
		
		CKSHA256 sha256 = new CKSHA256();
		byte[] digest1 = sha256.digest(message);

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest2 = md.digest(message);
			if (Arrays.equals(digest1, digest2)) {
				System.out.println("Message digest test 1 passed!");
			}
			else {
				System.out.println("Message digest test 1 failed!");
			}
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}		

	}

}
