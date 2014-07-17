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
import org.cryptokitty.keys.KeyAlgorithms;

/**
 * @author Steve Brenneis
 *
 */
public class PublicKeyEncryptedSessionKey {

	/*
	 * Multiprecision integer containing the first half of
	 * the ElGamal public key.
	 */
	private MPI elgamalMPI1;

	/*
	 * Multiprecision integer containing the second half of
	 * the ElGamal public key.
	 */
	private MPI elgamalMPI2;

	/*
	 * Key ID.
	 */
	private KeyID id;

	/*
	 * The raw, encrypted key.
	 */
	private byte[] keypacket;

	/*
	 * Public key algorithm
	 */
	private int pkAlgorithm;

	/*
	 * Multiprecision integer containing the RSA public key.
	 */
	private MPI rsaMPI;

	/*
	 * Packet version number. Should be 3.
	 */
	private int version;

	/**
	 * Constructs a PKESK from a raw packet.
	 */
	public PublicKeyEncryptedSessionKey(byte[] packet)
			throws InvalidPacketException {

		version = packet[0];
		try {
			id = new KeyID(Arrays.copyOfRange(packet, 1, 8));
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}
		pkAlgorithm = packet[9];
		keypacket = Arrays.copyOfRange(packet, 10, packet.length-1);
		ByteArrayInputStream in = new ByteArrayInputStream(keypacket);
		
		try {
			switch (pkAlgorithm) {
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_ENCRYPT:
				rsaMPI = new MPI(in);
				break;
			case KeyAlgorithms.ELGAMAL:
				elgamalMPI1 = new MPI(in);
				elgamalMPI2 = new MPI(in);
				break;
			default:
				throw new InvalidPacketException("Invalid public key algorithm");
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException("Invalid public key format");
		}

	}

}
