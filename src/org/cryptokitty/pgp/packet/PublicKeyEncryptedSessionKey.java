/**
 * 
 */
package org.cryptokitty.pgp.packet;

import java.io.IOException;
import java.io.InputStream;

//import org.cryptokitty.data.DataException;
//import org.cryptokitty.data.KeyID;
//import org.cryptokitty.data.MPI;
import org.cryptokitty.pgp.keys.KeyAlgorithms;

/**
 * @author Steve Brenneis
 *
 * The encrypted session key. Encrypted using an RSA or ElGamal
 * public key. See RFC 4880, section 5.1.
 */
public class PublicKeyEncryptedSessionKey {

	/*
	 * Multiprecision integer containing the first half of
	 * the ElGamal public key.
	 */
//	private MPI elgamalMPI1;

	/*
	 * Multiprecision integer containing the second half of
	 * the ElGamal public key.
	 */
//	private MPI elgamalMPI2;

	/*
	 * Key ID.
	 */
//	private KeyID id;

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
//	private MPI rsaMPI;

	/*
	 * Packet version number. Should be 3.
	 */
	private int version;

	/**
	 * Constructs a PKESK from a raw packet.
	 */
	public PublicKeyEncryptedSessionKey(InputStream in)
			throws InvalidPacketException {

		try {
			version = in.read();
//			try {
//				id = new KeyID(in);
//			}
//			catch (DataException e) {
//				throw new InvalidPacketException(e);
//			}

			pkAlgorithm = in.read();		
			/*switch (pkAlgorithm) {
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
			}*/
		}
		//catch (DataException e) {
		//	throw new InvalidPacketException("Invalid public key format");
		//}
		catch (IOException e) {
			throw new InvalidPacketException("Invalid public key format");
		}

	}

}
