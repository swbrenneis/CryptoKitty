/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;

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
//	private Time createTime;

	/*
	 * Multiprecision integer for r part of DSA signature.
	 */
//	private MPI dsaMPIr;

	/*
	 * Multiprecision integer for s part of DSA signature.
	 */
//	private MPI dsaMPIs;

	/*
	 * Hash algorithm.
	 */
	@SuppressWarnings("unused")
	private int hashAlgorithm;

	/*
	 * Hashed subpackets.
	 */
	@SuppressWarnings("unused")
	private SignatureSubpacketSet hashedSubpackets;

	/*
	 * PublicKey algorithm.
	 */
	@SuppressWarnings("unused")
	private int pkAlgorithm;

	/*
	 * Multiprecision integer for RSA signature.
	 */
//	private MPI rsaMPI;

	/*
	 * Signature type.
	 */
//	private int signatureType;

	/*
	 * Signer ID.
	 */
//	private KeyID signer;

	/*
	 * Unhashed subpackets.
	 */
	@SuppressWarnings("unused")
	private SignatureSubpacketSet unhashedSubpackets;

	/*
	 * Version number.
	 */
	private int version;

	/**
	 * Constructs a signature packet from a raw packet.
	 */
	public SignaturePacket(InputStream in)
			throws InvalidPacketException {

		/*
		 * TODO Check variable validity.
		 */
		try {
			version = in.read();
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

		if (version == 3) {
			readV3Packet(in);
		}
		else if (version == 4) {
			readV4Packet(in);
		}
		else {
			throw new InvalidPacketException("Illegal signature version");
		}

	}

	/*
	 * Read a version 3 signature packet. Byte 0 of the raw
	 * packet is the version number.
	 */
	private void readV3Packet(InputStream in)
			throws InvalidPacketException {
/*
		try {
			// This is supposed to be a length byte for the signature algorithm
			// and creation time. It must always be 5, so...
			int length = in.read();
			if (length != 5) {
				throw new InvalidPacketException("Illegal data length");
			}

			int signatureType = in.read();
			try {
				createTime = new Time(in);
				signer = new KeyID(in);
			}
			catch (DataException e) {
				throw new InvalidPacketException(e);
			}

			pkAlgorithm = in.read();
			hashAlgorithm = in.read();

			switch (pkAlgorithm) {
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_SIGN:
				rsaMPI = new MPI(in);
				break;
			case KeyAlgorithms.DSA:
				dsaMPIr = new MPI(in);
				dsaMPIs = new MPI(in);
				break;
			default:
				throw new InvalidPacketException("Invalid signture key");
			}
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
*/
	}

	/*
	 * Read a version 4 signature packet. Byte 0 of the raw
	 * packet is the version number.
	 */
	private void readV4Packet(InputStream in)
			throws InvalidPacketException {
/*
		try {
			signatureType = in.read();
			pkAlgorithm = in.read();
			hashAlgorithm = in.read();

			Scalar16 subpacketLength = new Scalar16(in);
			byte[] sBytes = new byte[subpacketLength.getValue()];
			in.read(sBytes);
			ByteArrayInputStream subin = new ByteArrayInputStream(sBytes);
			hashedSubpackets = new SignatureSubpacketSet(subin);

			subpacketLength = new Scalar16(in);
			sBytes = new byte[subpacketLength.getValue()];
			in.read(sBytes);
			subin = new ByteArrayInputStream(sBytes);
			unhashedSubpackets = new SignatureSubpacketSet(subin);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}
*/
	}

}
