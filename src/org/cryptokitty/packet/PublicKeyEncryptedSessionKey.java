/**
 * 
 */
package org.cryptokitty.packet;

import java.util.Arrays;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.KeyID;

/**
 * @author Steve Brenneis
 *
 */
public class PublicKeyEncryptedSessionKey {

	/*
	 * Public key algorithm
	 */
	private int algorithm;

	/*
	 * Key ID.
	 */
	private KeyID id;

	/*
	 * The raw, encrypted key.
	 */
	private byte[] keypacket;

	/*
	 * Packet version number.
	 */
	private int version;

	/**
	 * 
	 */
	public PublicKeyEncryptedSessionKey(byte[] packet)
			throws DataException {
		version = packet[0];
		id = new KeyID(Arrays.copyOfRange(packet, 1, 8));
		algorithm = packet[9];
		keypacket = Arrays.copyOfRange(packet, 10, packet.length-1);
	}

}
