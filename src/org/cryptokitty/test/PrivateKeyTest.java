/**
 * 
 */
package org.cryptokitty.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

import org.cryptokitty.keys.PGPPrivateKey;
import org.cryptokitty.packet.InvalidPacketException;
import org.cryptokitty.packet.PacketException;
import org.cryptokitty.packet.PacketReader;
import org.cryptokitty.packet.SecretKeyPacket;
import org.cryptokitty.provider.CryptoKittyProvider;

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
				PGPPrivateKey key = new PGPPrivateKey(keyPacket);
				System.out.println("Private key test 1 passed!");
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
