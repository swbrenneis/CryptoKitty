/**
 * 
 */
package org.cryptokitty.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.cryptokitty.keys.UnsupportedAlgorithmException;
import org.cryptokitty.packet.InvalidPacketException;
import org.cryptokitty.packet.PacketException;
import org.cryptokitty.packet.PacketReader;
import org.cryptokitty.packet.SecretKeyPacket;
import org.cryptokitty.provider.CryptoKittyProvider;
import org.cryptokitty.provider.S2KParameterSpec;

/**
 * @author stevebrenneis
 *
 */
public class PrivateKeyTest {

	/**
	 * 
	 */
	public PrivateKeyTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new CryptoKittyProvider());
		try {

			FileInputStream keyIn = new FileInputStream("sbrenneisPrivate.asc");
			PacketReader reader = new PacketReader();
			reader.readPacket(keyIn);
			if (reader.getPacketTag() == PacketReader.SECRET_KEY_PACKET) {
				InputStream in = reader.getInputStream();
				SecretKeyPacket keyPacket = new SecretKeyPacket("zct5j1IF", in);
				/*
				KeySpec keySpec = null;
				KeyFactory keyFactory = null;
				switch (keyPacket.getPKAlgorithm()) {
				case KeyAlgorithms.DSA:
					keySpec = new DSAPrivateKeySpec(keyPacket.getDSAPublicKey().toBigInteger(),
													keyPacket.getDSAPrime().toBigInteger(),
													keyPacket.getDSAGroupOrder().toBigInteger(),
													keyPacket.getDSAGroupGenerator().toBigInteger());
					keyFactory = KeyFactory.getInstance("DSA");
					break;
				case KeyAlgorithms.ELGAMAL:
					// Oops. No native Java support.
					break;
				case KeyAlgorithms.RSA:
				case KeyAlgorithms.RSA_ENCRYPT:
				case KeyAlgorithms.RSA_SIGN:
					keySpec = new RSAPrivateKeySpec(keyPacket.getRSAModulus().toBigInteger(),
													keyPacket.getRSAExponent().toBigInteger());
					keyFactory = KeyFactory.getInstance("RSA");
					break;
				}

				if (keySpec != null) {
					PrivateKey key = keyFactory.generatePrivate(keySpec);
				}
				else {
					System.err.println("Illegal public key algorithm.");
					System.err.println("Public key test 1 failed.");
				}
				*/
			}
			else {
				System.err.println("Not a private key packet");
			}

		}
		catch (IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Private key test 1 failed.");
		}
		catch (InvalidPacketException e) {
			System.err.println(e.getMessage());
			System.err.println("Private key test 1 failed.");
		}
		//catch (NoSuchAlgorithmException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}
		//catch (InvalidKeySpecException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}
		catch (PacketException e) {
			System.err.println(e.getMessage());
			System.err.println("Private key test 1 failed.");
		}
		//catch (NoSuchProviderException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}
		//catch (NoSuchPaddingException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}
		//catch (InvalidAlgorithmParameterException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}
		//catch (UnsupportedAlgorithmException e) {
		//	System.err.println(e.getMessage());
		//	System.err.println("Private key test 1 failed.");
		//}

	}

}
