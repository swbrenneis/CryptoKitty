/**
 * 
 */
package org.cryptokitty.packet;

import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * A public subkey packet is identical to a public key packet.
 * This class is meant to differentiate the two. It may disappear.
 */
public class PublicSubkey extends PublicKeyPacket {

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public PublicSubkey(InputStream in) throws InvalidPacketException {
		super(in);
		// TODO Auto-generated constructor stub
	}

}
