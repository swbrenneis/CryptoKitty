/**
 * 
 */
package org.cryptokitty.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptokitty.provider.CryptoKittyProvider;

/**
 * @author Steve Brenneis
 *
 */
public class CAST5Test {

	/**
	 * 
	 */
	public CAST5Test() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		byte[] plaintext =
			{ 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF };

		// 128 bit key
		byte[] key1 = 
			{ 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
				0x23, 0x45, 0x67, (byte)0x89, 0x34, 0x56, 0x78, (byte)0x9A };
	
		byte[] ciphertext1 = 
			{ 0x23, (byte)0x8B, 0x4F, (byte)0xE5, (byte)0x84, 0x7E, 0x44, (byte)0xB2 };

		// 80 bit key
		byte[] key2 =
			{ 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45 };

		byte[] ciphertext2 =
			{ (byte)0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B };

		// 40 bit key
		byte[] key3 = { 0x01, 0x23, 0x45, 0x67, 0x12 };

		byte[] ciphertext3 =
			{ 0x7A, (byte)0xC8, 0x16, (byte)0xD1, 0x6E, (byte)0x9B, 0x30, 0x2E };

		// CFB 128 bit key
		byte[] cfbKey1 =
			{ 0x08, 0x5b, (byte)0x8a, (byte)0xf6, 0x78, (byte)0x8f, (byte)0xa6, (byte)0xbc,
				0x1a, 0x0b, 0x47, (byte)0xdc, (byte)0xf5, 0x0f, (byte)0xbd, 0x35 };

		byte[] iv1 = { 0x58, (byte)0xcb, 0x2b, 0x12, (byte)0xbb, 0x52, (byte)0xc6, (byte)0xf1 };

		byte[] cfbPlaintext1 = 
			{ 0x4b, 0x5a, (byte)0x87, 0x22, 0x60, 0x29, 0x33, 0x12, (byte)0xee,
				(byte)0xa1, (byte)0xa5, 0x70, (byte)0xfd, 0x39, (byte)0xc7, (byte)0x88 };

		byte[] cfbCiphertext1 =
			{ 0x45, 0x3d, 0x00, (byte)0xcb, 0x11, (byte)0xe1, (byte)0xcf, 0x4e, 0x52,
				(byte)0xee, 0x11, (byte)0xc1, (byte)0xc2, 0x2c, (byte)0xd6, (byte)0xb6 };

       try {

    	   Security.addProvider(new CryptoKittyProvider());

    	   // Test 1 - 128 bit key
			Cipher cipher = Cipher.getInstance("CAST5", "CryptoKitty");
			TestKey key = new TestKey(key1);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] c = cipher.doFinal(plaintext);
			if (Arrays.equals(c, ciphertext1)) {
				System.out.println("CAST5 block mode encryption test 1 passed!");
				cipher = Cipher.getInstance("CAST5", "CryptoKitty");
				cipher.init(Cipher.DECRYPT_MODE, key);
				byte[] m = cipher.doFinal(ciphertext1);
				if (Arrays.equals(m, plaintext)) {
					System.out.println("CAST5 block mode decryption test 1 passed!");
				}
				else {
					System.out.println("CAST5 block mode decryption test 1 failed.");				
				}
			}
			else {
				System.out.println("CAST5 block mode encryption test 1 failed.");				
			}

			// Test 1 - 128 bit key
			cipher = Cipher.getInstance("CAST5", "CryptoKitty");
			key = new TestKey(key2);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			c = cipher.doFinal(plaintext);
			if (Arrays.equals(c, ciphertext2)) {
				System.out.println("CAST5 block mode encryption test 2 passed!");
				cipher = Cipher.getInstance("CAST5", "CryptoKitty");
				cipher.init(Cipher.DECRYPT_MODE, key);
				byte[] m = cipher.doFinal(ciphertext2);
				if (Arrays.equals(m, plaintext)) {
					System.out.println("CAST5 block mode decryption test 2 passed!");
				}
				else {
					System.out.println("CAST5 block mode decryption test 2 failed.");				
				}
			}
			else {
				System.out.println("CAST5 block mode encryption test 2 failed.");				
			}

			// Test 3 - 40 bit key
			cipher = Cipher.getInstance("CAST5", "CryptoKitty");
			key = new TestKey(key3);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			c = cipher.doFinal(plaintext);
			if (Arrays.equals(c, ciphertext3)) {
				System.out.println("CAST5 block mode encryption test 3 passed!");
				cipher = Cipher.getInstance("CAST5", "CryptoKitty");
				cipher.init(Cipher.DECRYPT_MODE, key);
				byte[] m = cipher.doFinal(ciphertext3);
				if (Arrays.equals(m, plaintext)) {
					System.out.println("CAST5 block mode decryption test 3 passed!");
				}
				else {
					System.out.println("CAST5 block mode decryption test 3 failed.");				
				}
			}
			else {
				System.out.println("CAST5 block mode encryption test 3 failed.");				
			}

			// Test 1 - CFB mode, 128 bit key
			cipher = Cipher.getInstance("CAST5/CFB/NoPadding", "CryptoKitty");
			key = new TestKey(cfbKey1);
			IvParameterSpec iv = new IvParameterSpec(iv1);
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			c = cipher.doFinal(cfbPlaintext1);
			if (Arrays.equals(c, cfbCiphertext1)) {
				System.out.println("CAST5 CFB mode encryption test 1 passed!");
				cipher = Cipher.getInstance("CAST5/CFB/NoPadding", "CryptoKitty");
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
				byte[] m = cipher.doFinal(cfbCiphertext1);
				if (Arrays.equals(m, cfbPlaintext1)) {
					System.out.println("CAST5 CFB mode decryption test 1 passed!");
				}
				else {
					System.out.println("CAST5 CFB mode decryption test 1 failed.");				
				}
			}
			else {
				System.out.println("CAST5 CFB mode encryption test 1 failed.");				
			}


		}
		catch (InvalidKeyException e) {
			e.printStackTrace();
		}
       catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
       catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
       catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
       catch (IllegalBlockSizeException e) {
		e.printStackTrace();
       }
       catch (BadPaddingException e) {
		e.printStackTrace();
       }
       catch (InvalidAlgorithmParameterException e) {
		e.printStackTrace();
       }

	}

}
