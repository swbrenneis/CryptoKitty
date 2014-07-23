/**
 * 
 */
package org.cryptokitty.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;

import org.cryptokitty.keys.KeyAlgorithms;
import org.cryptokitty.packet.InvalidPacketException;
import org.cryptokitty.packet.PacketException;
import org.cryptokitty.packet.PacketReader;
import org.cryptokitty.packet.SecretKeyPacket;

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
		try {

			FileInputStream keyIn = new FileInputStream("sbrenneisPrivate.asc");
			PacketReader reader = new PacketReader();
			reader.readPacket(keyIn);
			if (reader.getPacketTag() == PacketReader.SECRET_KEY_PACKET) {
				InputStream in = reader.getInputStream();
				SecretKeyPacket keyPacket = new SecretKeyPacket("zct5j1IF", in);
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
			}
			else {
				System.err.println("Not a private key packet");
			}

		}
		catch (IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Public key test 1 failed.");
		}
		catch (InvalidPacketException e) {
			System.err.println(e.getMessage());
			System.err.println("Public key test 1 failed.");
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			System.err.println("Public key test 1 failed.");
		}
		catch (InvalidKeySpecException e) {
			System.err.println(e.getMessage());
			System.err.println("Public key test 1 failed.");
		}
		catch (PacketException e) {
			System.err.println(e.getMessage());
			System.err.println("Public key test 1 failed.");
		}

	}

}
