/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.data.MPI;
import org.cryptokitty.keys.KeyAlgorithms;
import org.cryptokitty.keys.String2Key;

/**
 * @author Steve Brenneis
 *
 * A secret key packet is really just a public key packet with
 * the secret key appended to the end. See RFC 4880, section 5.3.3.
 */
public class SecretKey extends PublicKey {

	/*
	 * DSA secret exponent x.
	 */
	protected MPI dsaX;

	/*
	 * ElGamal secret exponent x.
	 */
	protected MPI elgamalX;

	/*
	 * Encryption indicator.
	 */
	protected boolean encrypted;

	/*
	 * Initial vector for secret key encryption.
	 */
	protected byte[] initialVector;

	/*
	 * Symmetric algorithm for encrypted key.
	 */
	protected int keyAlgorithm;

	/*
	 * RSA secret key p prime.
	 */
	protected MPI rsaP;

	/*
	 * RSA secret key q prime.
	 */
	protected MPI rsaQ;

	/*
	 * RSA secret key multiplicative inverse of p mod q.
	 */
	protected MPI rsaU;

	/*
	 * String 2 key specifier.
	 */
	protected String2Key s2k;

	/*
	 * String 2 key usage indicator. 254 or 255 indicate s2k in use.
	 */
	protected int s2kUsage;

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public SecretKey(InputStream in) throws InvalidPacketException {
		super(in);
		// TODO Variable validation.

		try {
			encrypted = true;
			s2kUsage = in.read();
			if (s2kUsage == 254 || s2kUsage == 255) {
				keyAlgorithm = in.read();
				s2k = String2Key.getS2K(in);
			}
			else if (s2kUsage == 0) {
				encrypted = false;
			}
			else {
				keyAlgorithm = in.read();
			}

			if (encrypted) {
				switch (keyAlgorithm) {
				case KeyAlgorithms.IDEA:
				case KeyAlgorithms.TRIPLE_DES:
				case KeyAlgorithms.CAST5:
				case KeyAlgorithms.BLOWFISH:
					initialVector = new byte[8];
					break;
				case KeyAlgorithms.AES128:
				case KeyAlgorithms.TWOFISH:
					initialVector = new byte[16];
					break;
				case KeyAlgorithms.AES192:
					initialVector = new byte[24];
					break;
				case KeyAlgorithms.AES256:
					initialVector = new byte[32];
					break;
				default:
					throw new InvalidPacketException("Illegal symmetric algorithm");
				}
				in.read(initialVector);
			}

			switch (pkAlgorithm) {	// From public key.
			case KeyAlgorithms.DSA:
				dsaX = new MPI(in);
				break;
			case KeyAlgorithms.ELGAMAL:
				elgamalX = new MPI(in);
				break;
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_ENCRYPT:
			case KeyAlgorithms.RSA_SIGN:
				rsaP = new MPI(in);
				rsaQ = new MPI(in);
				rsaU = new MPI(in);
				break;
			default:
				throw new InvalidPacketException("Illegal public key algorithm");
			}

		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
	}

}
