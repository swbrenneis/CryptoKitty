/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * @author Steve Brenneis
 *
 * Reads and maintains an ordered set of signature subpackets.
 * See RFC 4880, section 5.2.3.1.
 */
public class SignatureSubpacketSet {

	/*
	 * Subpacket types
	 */
	public static final int SIGNATURE_CREATE_TIME = 2;
	public static final int SIGNATURE_EXPIRE_TIME = 3;
	public static final int EXPORTABLE_CERTIFICATION = 4;
	public static final int TRUST_SIGNATURE = 5;
	public static final int REGEX = 6;
	public static final int REVOCABLE = 7;
	public static final int KEY_EXPIRE_TIME = 9;
	public static final int PREFERRED_SYMMETRIC = 11;
	public static final int REVOCATION_KEY = 12;
	public static final int ISSUER = 16;
	public static final int NOTATION_DATA = 20;
	public static final int PREFERRED_HASH = 21;
	public static final int PREFERRED_COMPRESSION = 22;
	public static final int KEY_SERVER_PREFS = 23;
	public static final int PREFERRED_KEY_SERVER = 24;
	public static final int PRIMARY_USER_ID = 25;
	public static final int POLICY_URI = 26;
	public static final int KEY_FLAGS = 27;
	public static final int SIGNER_USER_ID = 28;
	public static final int REVOCATION_REASON = 29;
	public static final int FEATURES = 30;
	public static final int SIGNATURE_TARGET = 31;
	public static final int EMBEDDED_SIGNATURE = 32;

	/*
	 * Subpacket POD.
	 */
	private class Subpacket {
		public Subpacket(int type, byte[] blob,
									boolean critical) {
			this.type = type;
			this.blob = blob;
			this.critical = critical;
		}
		public int type;
		public byte[] blob;
		public boolean critical;
	}

	/*
	 * The subpackets.
	 */
	private ArrayList<Subpacket> subpackets;

	/**
	 * 
	 */
	public SignatureSubpacketSet(InputStream in)
			throws InvalidPacketException {

		subpackets = new ArrayList<Subpacket>();

		try {
			int lengthByte = in.read();
			while (lengthByte > 0) {
				int packetLength = 0;
				if (lengthByte < 192) {
					packetLength = lengthByte;
				}
				else if (lengthByte < 223){
					packetLength = (lengthByte - 192) << 8;
					lengthByte = in.read();
					packetLength += (lengthByte + 192);
				}
				else if (lengthByte == 255){
					byte[] pl = new byte[4];
					in.read(pl);
					for (byte b : pl) {
						packetLength = packetLength << 8;
						packetLength = packetLength | ((int)b & 0xff);
					}
				}
				else {
					throw new InvalidPacketException("Invalid length type");
				}
				int type = in.read();
				byte[] blob = new byte[packetLength-1];
				in.read(blob);
				boolean critical = (type & 0x80) != 0;
				Subpacket sub = new Subpacket((type & 0x7f), blob, critical);
				subpackets.add(sub);
				lengthByte = in.read();
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		
	}

}
