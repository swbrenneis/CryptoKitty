/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author stevebrenneis
 *
 * This class fulfills the general PGP packet implementation.
 * See RFC 4880, section 4.2.
 */
public class PacketReader {
	
	/*
	 * Packet header constants.
	 */
	public static final byte BASE_PACKET_TAG = (byte)0x80;
	public static final byte NEW_PACKET_TAG = (byte)0x40;
	public static final byte OLD_TAG_MASK = (byte)0x3C;
	public static final byte OLD_LENGTH_TYPE_MASK = (byte)0x03;
	public static final byte NEW_TAG_MASK = (byte)0x3F;
	public static final byte PACKET_LENGTH_ONE = 0;
	public static final byte PACKET_LENGTH_TWO = 1;
	public static final byte PACKET_LENGTH_FOUR = 2;
	public static final byte PACKET_LENGTH_IND = 3; // Not supported

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
	protected PacketReader() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * Read a new style packet
	 */
	private void readNewPacket(int tag, InputStream in)
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
			// Partial packets. Yuck.
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
	private void readOldPacket(int tag, InputStream in)
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
	protected void readPacket(InputStream in)
			throws IOException, PacketException {
		
		// Get the packet tag.
		int tag = in.read();
		// Check to see if it is a packet tag.
		if ((tag & BASE_PACKET_TAG) == 0) {
			throw new PacketException("Not a packet tag");
		}

		if ((tag & NEW_PACKET_TAG) != 0) {
			readNewPacket(tag, in);
		}
		else {
			readOldPacket(tag, in);
		}

	}

	/*
	 * Recursive method for reading partial packets.
	 */
	private void readPartialPackets(InputStream in) {
		
	}

}
