/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * The contents of a secret subkey are identical to a secret key.
 * THis class is here just for differentiation. It may disappear.
 */
public class SecretSubkeyPacket extends SecretKeyPacket {

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public SecretSubkeyPacket(String passPhrase, InputStream in) throws InvalidPacketException {
		super(passPhrase,in);
		// TODO Auto-generated constructor stub
	}

}
