/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.MPI;
import org.cryptokitty.data.Scalar;
import org.cryptokitty.data.Time;
import org.cryptokitty.keys.KeyAlgorithms;

/**
 * @author Steve Brenneis
 *
 */
public class PublicKey {

	/*
	 * Creation time.
	 */
	protected Time createTime;

	/*
	 * DSA group generator.
	 */
	protected MPI dsaGroupGenerator;

	/*
	 * DSA group order.
	 */
	protected MPI dsaGroupOrder;

	/*
	 * DSA prime.
	 */
	protected MPI dsaPrime;

	/*
	 * ElGamal group generator.
	 */
	protected MPI elgamalGroupGenerator;

	/*
	 * ElGamal prime.
	 */
	protected MPI elgamalPrime;

	/*
	 * ElGamal public key value y.
	 */
	protected MPI elgamalY;

	/*
	 * Expiration time in days. Zero = no expiration.
	 */
	protected int expires;

	/*
	 * Public key algorithm.
	 */
	protected int pkAlgorithm;

	/*
	 * RSA encryption exponent.
	 */
	protected MPI rsaExponent;

	/*
	 * RSA modulus n value.
	 */
	protected MPI rsaModulus;

	/*
	 * Packet version. Version 3 packets are deprecated.
	 */
	protected int version;

	/**
	 * 
	 */
	public PublicKey(InputStream in)
		throws InvalidPacketException {
		// TODO Variable checking.

		try {
			version = in.read();
			switch (version) {
			case 3:					// Deprecated.
				readV3Packet(in);
				break;
			case 4:
				readV4Packet(in);
			default:
				throw new InvalidPacketException("Illegal version number");
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Read a version 3 packet. Version 3 packets are deprecated.
	 */
	protected void readV3Packet(InputStream in)
			throws InvalidPacketException {

		try {
			createTime = new Time(in);
			expires = new Scalar(in).getValue();
			pkAlgorithm = in.read();
			rsaModulus = new MPI(in);
			rsaExponent = new MPI(in);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Read a version 4 packet.
	 */
	protected void readV4Packet(InputStream in)
			throws InvalidPacketException {

		try {
			createTime = new Time(in);
			pkAlgorithm = in.read();
			switch (pkAlgorithm) {
			case KeyAlgorithms.DSA:
				dsaPrime = new MPI(in);
				dsaGroupOrder = new MPI(in);
				dsaGroupGenerator = new MPI(in);
				break;
			case KeyAlgorithms.ELGAMAL:
				elgamalPrime = new MPI(in);
				elgamalGroupGenerator = new MPI(in);
				elgamalY = new MPI(in);
				break;
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_ENCRYPT:
			case KeyAlgorithms.RSA_SIGN:
				rsaModulus = new MPI(in);
				rsaExponent = new MPI(in);
				break;
			default:
				throw new InvalidPacketException("Illegal public key algorithm");
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}

	}

}
