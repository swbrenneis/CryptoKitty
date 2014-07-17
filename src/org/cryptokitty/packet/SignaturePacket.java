/**
 * 
 */
package org.cryptokitty.packet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.KeyID;
import org.cryptokitty.data.MPI;
import org.cryptokitty.data.Time;
import org.cryptokitty.keys.KeyAlgorithms;

/**
 * @author Steve Brenneis
 *
 * A packet containing a signature for signed data.
 * 
 */
public class SignaturePacket {

	/*
	 * Signature type constants.
	 */
	public static final int BINARY_DOCUMENT = 0x00;
	public static final int CANONICAL_TEXT = 0x01;
	public static final int STANDALONE = 0x02;
	public static final int ID_AND_KEY = 0x10;
	public static final int PERSONA_ID_AND_KEY = 0x11;
	public static final int CASUAL_ID_AND_KEY = 0x12;
	public static final int POSITIVE_ID_AND_KEY = 0x13;
	public static final int SUBKEY_BINDING = 0x18;
	public static final int PRIMARY_KEY_BINDING = 0x19;
	public static final int DIRECT_KEY = 0x1F;
	public static final int KEY_REVOCATION = 0x20;
	public static final int SUBKEY_REVOCATION = 0x28;
	public static final int CERTIFICATION_REVOCATION = 0x30;
	public static final int TIMESTAMP = 0x40;
	public static final int THIRD_PARTY = 0x50;

	/*
	 * Creation time.
	 */
	private Time createTime;

	/*
	 * Multiprecision integer for r part of DSA signature.
	 */
	private MPI dsaMPIr;

	/*
	 * Multiprecision integer for s part of DSA signature.
	 */
	private MPI dsaMPIs;

	/*
	 * Hash algorithm.
	 */
	private int hashAlgorithm;

	/*
	 * PublicKey algorithm.
	 */
	private int pkAlgorithm;

	/*
	 * Multiprecision integer for RSA signature.
	 */
	private MPI rsaMPI;

	/*
	 * Signature type.
	 */
	private int signatureType;

	/*
	 * Signer ID.
	 */
	private KeyID signer;

	/*
	 * Version number.
	 */
	private int version;

	/**
	 * Constructs a signature packet from a raw packet.
	 */
	public SignaturePacket(byte[] packet)
			throws InvalidPacketException {

		version = packet[0];

		if (version == 3) {
			readV3Packet(packet);
		}
		else if (version == 4) {
			readV4Packet(packet);
		}
		else {
			throw new InvalidPacketException("Illegal signature version");
		}

	}

	/*
	 * Read a version 3 signature packet. Byte 0 of the raw
	 * packet is the version number.
	 */
	private void readV3Packet(byte[] packet)
			throws InvalidPacketException {

		// This is supposed to be a length byte for the signature algorithm
		// and creation time. It must always be 5, so...
		if (packet[1] != 5) {
			throw new InvalidPacketException("Illegal data length");
		}
	
		signatureType = packet[2];
		try {
			createTime = new Time(Arrays.copyOfRange(packet, 3, 6));
			signer = new KeyID(Arrays.copyOfRange(packet, 7, 14));
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}

		pkAlgorithm = packet[15];
		hashAlgorithm = packet[16];

		ByteArrayInputStream in =
				new ByteArrayInputStream(Arrays.copyOfRange(packet, 16, packet.length-1));
		try {
			switch (pkAlgorithm) {
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_SIGN:
				rsaMPI = new MPI(in);
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
	}

	/*
	 * Read a version 4 signature packet. Byte 0 of the raw
	 * packet is the version number.
	 */
	private void readV4Packet(byte[] packet)
			throws InvalidPacketException {
		
	}

}
