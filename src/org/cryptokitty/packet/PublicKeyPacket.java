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
public class PublicKeyPacket {

	/*
	 * Creation time.
	 */
	protected Time createTime;

	/*
	 * DSA group generator (g).
	 */
	protected MPI dsaGroupGenerator;

	/*
	 * DSA group order (q).
	 */
	protected MPI dsaGroupOrder;

	/*
	 * DSA prime (p).
	 */
	protected MPI dsaPrime;

	/*
	 * DSA public key (y).
	 */
	protected MPI dsaPublicKey;

	/*
	 * ElGamal group generator (g).
	 */
	protected MPI elgamalGroupGenerator;

	/*
	 * ElGamal prime (p).
	 */
	protected MPI elgamalPrime;

	/*
	 * ElGamal public key (y).
	 */
	protected MPI elgamalPublicKey;

	/*
	 * Expiration time in days. Zero = no expiration.
	 */
	protected int expires;

	/*
	 * Public key algorithm.
	 */
	protected int pkAlgorithm;

	/*
	 * RSA exponent (e).
	 */
	protected MPI rsaExponent;

	/*
	 * RSA modulus (n).
	 */
	protected MPI rsaModulus;

	/*
	 * Packet version. Version 3 packets are deprecated.
	 */
	protected int version;

	/**
	 * 
	 */
	public PublicKeyPacket(InputStream in)
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
				break;
			default:
				throw new InvalidPacketException("Illegal version number");
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Returns the DSA group generator (g).
	 */
	public MPI getDSAGroupGenerator() {
		return dsaGroupGenerator;
	}

	/*
	 * Returns the DSA group order (q).
	 */
	public MPI getDSAGroupOrder() {
		return dsaGroupOrder;
	}

	/*
	 * Returns the DSA prime (p).
	 */
	public MPI getDSAPrime() {
		return dsaPrime;
	}

	/*
	 * Returns the DSA public key (y).
	 */
	public MPI getDSAPublicKey() {
		return dsaPublicKey;
	}

	/*
	 * Returns the ElGamal group generator (g).
	 */
	public MPI getElGamalGroupGenerator() {
		return elgamalGroupGenerator;
	}

	/*
	 * Returns the ElGamal prime (p).
	 */
	public MPI getElGamalPrime() {
		return elgamalPrime;
	}

	/*
	 * Returns the ElGamal public key (y).
	 */
	public MPI getElGamalPublicKey() {
		return elgamalPublicKey;
	}

	/*
	 * Returns the RSA exponent.
	 */
	public MPI getRSAExponent() {
		return rsaExponent;
	}

	/*
	 * Returns the RSA modulus.
	 */
	public MPI getRSAModulus() {
		return rsaModulus;
	}

	/*
	 * Returns the public key algorithm. DSA and RSA are currently
	 * supported.
	 */
	public int getPKAlgorithm() {
		return pkAlgorithm;
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
				dsaPublicKey = new MPI(in);
				break;
			case KeyAlgorithms.ELGAMAL:
				elgamalPrime = new MPI(in);
				elgamalGroupGenerator = new MPI(in);
				elgamalPublicKey = new MPI(in);
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
