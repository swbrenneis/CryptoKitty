/**
 * 
 */
package org.cryptokitty.packet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

import org.cryptokitty.encode.ArmoredData;
import org.cryptokitty.encode.EncodingException;

/**
 * @author Steve Brenneis
 *
 * This class fulfills the general PGP packet implementation.
 * See RFC 4880, section 4.2.
 */
public class PacketReader {
	
	/*
	 * Packet header constants.
	 */
	public static final int BASE_PACKET_TAG = 0x80;
	public static final int NEW_PACKET_TAG = 0x40;
	public static final int OLD_TAG_MASK = 0x3C;
	public static final int OLD_LENGTH_TYPE_MASK = 0x03;
	public static final int NEW_TAG_MASK = 0x3F;
	public static final int PACKET_LENGTH_ONE = 0;
	public static final int PACKET_LENGTH_TWO = 1;
	public static final int PACKET_LENGTH_FOUR = 2;
	public static final int PACKET_LENGTH_IND = 3; // Not supported

	/*
	 * Packet types.
	 */
	public static final int PUPLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET= 1;
	public static final int SIGNATURE_PACKET= 2;
	public static final int SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET = 3;
	public static final int ONE_PASS_SIGNATURE_PACKET = 4;
	public static final int SECRET_KEY_PACKET = 5;
	public static final int PUBLIC_KEY_PACKET = 6;
	public static final int SECRET_SUBKEY_PACKET = 7;
	public static final int COMPRESSED_DATA_PACKET = 8;
	public static final int SYMMETRIC_ENCRYPTED_DATA_PACKET = 9;
	public static final int MARKER_PACKET = 10;
	public static final int LITERAL_DATA_PACKET = 11;
	public static final int TRUST_PACKET = 12;
	public static final int USER_ID_PACKET = 13;
	public static final int PUBLIC_SUBKEY_PACKET = 14;
	public static final int USER_ATTRIBUTE_PACKET = 17;
	public static final int SYMMETRIC_ENCRYPTED_INTEGRITY_PROTECTED_DATA_PACKET = 18;	// Gesundheit
	public static final int MODIFICATION_DETECTION_CODE_PACKET = 19;

	/*
	 * The raw packet.
	 */
	protected byte[] packet;

	/*
	 * The packet type tag.
	 */
	protected int packetTag;

	/**
	 * 
	 */
	public PacketReader() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * Returns a byte array input stream based on the packet array.
	 */
	public InputStream getInputStream() {
		return new ByteArrayInputStream(packet);
	}

	/*
	 * Returns the whole packet.
	 */
	public byte[] getPacket() {
		return packet;
	}

	/*
	 * Returns the packet tag.
	 */
	public int getPacketTag() {
		return packetTag;
	}

	/*
	 * Read a new style packet
	 */
	private void readNewFormatPacket(int tag, InputStream in)
			throws InvalidPacketException, IOException {

		int lengthByte = in.read();
		int packetLength = 0;
		boolean partial = false;
		if (lengthByte < 192) {
			packetLength = lengthByte;
		}
		else if (lengthByte < 223){
			packetLength = (lengthByte - 192) << 8;
			lengthByte = in.read();
			packetLength += (lengthByte + 192);
		}
		else if (lengthByte < 255) {
			// Partial body length packets. Yuck.
			readPartialPackets(in);
			partial = true;
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

		if (!partial) {
			if (packetLength < 1) {
				throw new InvalidPacketException("Zero length packets not supported");
			}

			packet = new byte[packetLength];
			in.read(packet);
		}

		packetTag = tag & NEW_TAG_MASK;

	}

	/*
	 * Read an old style packet
	 */
	private void readOldFormatPacket(int tag, InputStream in)
			throws InvalidPacketException, IOException {

		int lengthType = tag & OLD_LENGTH_TYPE_MASK;
		byte[] pl = null;
		switch (lengthType) {
		case PACKET_LENGTH_ONE:
			pl = new byte[1];
			break;
		case PACKET_LENGTH_TWO:
			pl = new byte[2];
			break;
		case PACKET_LENGTH_FOUR:
			pl = new byte[4];
		case PACKET_LENGTH_IND:
			throw new InvalidPacketException("Unsupported packet length type");
		}

		if (pl == null) {
			throw new InvalidPacketException("Unknown packet length type - "
										+ String.valueOf(tag&OLD_LENGTH_TYPE_MASK));
		}

		in.read(pl);
		int packetLength = 0;
		for (byte b : pl) {
			packetLength = packetLength << 8;
			packetLength = packetLength | ((int)b & 0xff);
		}

		if (packetLength < 1) {
			throw new InvalidPacketException("Zero length packets not supported");
		}

		packet = new byte[packetLength];
		in.read(packet);
		
		packetTag = (tag & OLD_TAG_MASK) >> 2;

	}

	/*
	 * Read a packet in from a stream.
	 */
	public void readPacket(InputStream in)
			throws IOException, PacketException {

		// Check to see if the input is armored.
		PushbackInputStream pbi = new PushbackInputStream(in);
		InputStream decoded = pbi;
//		byte[] header = new byte[5];
		int first = pbi.read();
		pbi.unread(first);
		if (first == '-') {
			// Armored input
			ArmoredData armored = new ArmoredData();
			try {
				armored.decode(pbi);
				decoded = new ByteArrayInputStream(armored.getData());
			}
			catch (EncodingException e) {
				throw new InvalidPacketException(e);
			}
		}
		// Get the packet tag.
		int tag = decoded.read();
		// Check to see if it is a packet tag.
		if ((tag & BASE_PACKET_TAG) == 0) {
			throw new PacketException("Not a packet tag");
		}

		if ((tag & NEW_PACKET_TAG) != 0) {
			readNewFormatPacket(tag, decoded);
		}
		else {
			readOldFormatPacket(tag, decoded);
		}

	}

	/*
	 * Read partial body length packets.
	 */
	private void readPartialPackets(InputStream in) {
		// I don't know how to handle this yet.
	}

}
