/**
 * 
 */
package org.cryptokitty.packet;

import java.io.IOException;
import java.io.InputStream;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.MPI;
import org.cryptokitty.data.Scalar;
import org.cryptokitty.keys.KeyAlgorithms;
import org.cryptokitty.keys.String2Key;

/**
 * @author Steve Brenneis
 *
 * A secret key packet is really just a public key packet with
 * the secret key appended to the end. See RFC 4880, section 5.3.3.
 */
public class SecretKeyPacket extends PublicKeyPacket {

	/*
	 * Checksum (sum modulus 65536) of cleartext key material.
	 */
	protected Scalar checksum;

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
	 * RSA secret key exponent (d).
	 */
	protected MPI rsaSecretExponent;

	/*
	 * RSA secret key prime (p).
	 */
	protected MPI rsaSecretPrimeP;

	/*
	 * RSA secret key prime (q).
	 */
	protected MPI rsaSecretPrimeQ;

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

	/*
	 * SHA-1 hash of cleartext key material.
	 */
	protected byte[] sha1;

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public SecretKeyPacket(String passPhrase, InputStream in) throws InvalidPacketException {
		super(in);
		// TODO Variable validation.

		try {
			encrypted = true;
			s2kUsage = in.read();
			if (s2kUsage == 254 || s2kUsage == 255) {
				keyAlgorithm = in.read();
				s2k = String2Key.getS2K(in, passPhrase);
			}
			else if (s2kUsage == 0) {
				encrypted = false;
			}
			else {
				// Deprecated. TODO Decide whether to support it.
				// keyAlgorithm = in.read();
				throw new InvalidPacketException("Passphrase hash keys deprecated");
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
				rsaSecretExponent = new MPI(in);
				rsaSecretPrimeP = new MPI(in);
				rsaSecretPrimeQ = new MPI(in);
				rsaU = new MPI(in);
				break;
			default:
				throw new InvalidPacketException("Illegal public key algorithm");
			}

			if (s2kUsage == 254) {
				sha1 = new byte[20];
				in.read(sha1);
			}
			else {
				// s2kUsage 0 or 255. All others deprecated and unsupported.
				checksum = new Scalar(in);
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
