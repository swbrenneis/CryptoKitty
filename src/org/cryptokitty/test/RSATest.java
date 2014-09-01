/**
 * 
 */
package org.cryptokitty.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.cryptokitty.data.Scalar64;
import org.cryptokitty.provider.CryptoKittyProvider;
import org.cryptokitty.provider.digest.CKMD5;
import org.cryptokitty.provider.digest.Digest;

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

		try {

			KeyPairGenerator keyGen;
			// Generate a key pair.
			keyGen = KeyPairGenerator.getInstance("RSA", "CryptoKitty");
			keyGen.initialize(2048);
			KeyPair ckpair = keyGen.generateKeyPair();

			//keyGen = KeyPairGenerator.getInstance("RSA");
			//keyGen.initialize(2048);
			//KeyPair sunpair = keyGen.generateKeyPair();

			Digest digest = new CKMD5();
			byte[] message = digest.digest(Scalar64.encode(System.nanoTime()));

			// Test the key with the Sun RSA Cipher
/*			Cipher sunrsae = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
			sunrsae.init(Cipher.ENCRYPT_MODE, ckpair.getPublic());
			byte[] ciphertext = sunrsae.doFinal(message);

			Cipher sunrsad = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
			sunrsad.init(Cipher.DECRYPT_MODE, ckpair.getPrivate());
			byte[] plaintext = sunrsad.doFinal(ciphertext);

			if (Arrays.equals(message, plaintext)) {
				System.out.println("RSA Key test passed!");
			}
			else {
				System.out.println("RSA Key test failed!");;				
			}
*/

			Cipher rsae = Cipher.getInstance("RSA", "CryptoKitty");
			rsae.init(Cipher.ENCRYPT_MODE, ckpair.getPublic(),
					new OAEPParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"),
											new PSource.PSpecified(new byte[0])));
			byte[] ciphertext = rsae.doFinal(message);

			Cipher rsad = Cipher.getInstance("RSA", "CryptoKitty");
			rsad.init(Cipher.DECRYPT_MODE, ckpair.getPrivate(),
			new OAEPParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"),
					new PSource.PSpecified(new byte[0])));
			byte[] plaintext = rsad.doFinal(ciphertext);
			if (Arrays.equals(message, plaintext)) {
				System.out.println("RSA OEAP test passed!");
			}
			else {
				System.out.println("RSA OAEP test failed!");;				
			}

			rsae = Cipher.getInstance("RSA", "CryptoKitty");
			rsae.init(Cipher.ENCRYPT_MODE, ckpair.getPublic());
			ciphertext = rsae.doFinal(message);

			rsad = Cipher.getInstance("RSA", "CryptoKitty");
			rsad.init(Cipher.DECRYPT_MODE, ckpair.getPrivate());
			plaintext = rsad.doFinal(ciphertext);
			if (Arrays.equals(message, plaintext)) {
				System.out.println("RSA PKCS test passed!");
			}
			else {
				System.out.println("RSA PKCS test failed!");;				
			}

		}
		catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (NoSuchProviderException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (NoSuchPaddingException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (IllegalBlockSizeException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (BadPaddingException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}
		catch (InvalidAlgorithmParameterException e) {
			System.err.println(e.getMessage());
			System.out.println("RSA OAEP test failed!");;
		}

	}

}
