/**
 * 
 */
package org.cryptokitty.packet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptokitty.data.DataException;
import org.cryptokitty.data.MPI;
import org.cryptokitty.data.Scalar16;
import org.cryptokitty.data.Scalar32;
import org.cryptokitty.keys.KeyAlgorithms;
import org.cryptokitty.keys.String2Key;
import org.cryptokitty.keys.UnsupportedAlgorithmException;
import org.cryptokitty.provider.S2KParameterSpec;

/**
 * @author Steve Brenneis
 *
 * A secret key packet is really just a public key packet with
 * the secret key appended to the end. See RFC 4880, section 5.3.3.
 */
public class SecretKeyPacket extends PublicKeyPacket {

	/*
	 * Convenience class to abstract the checksum method.
	 */
	private class Checksum {
		// SHA-1 hash
		private MessageDigest sha1;
		// Checksum summation.
		private Scalar16 summation;
		// usage, 255 = checksum, 254 = hash
		private int usage;
		// usage determines whether it is a 2 octet modulus 65536 sum
		// or a SHA-1 hash.
		public Checksum(int usage) {
			this.usage = usage;
			if (usage == 255) {
				summation = new Scalar16(0);
			}
			else {
				try {
					sha1 = MessageDigest.getInstance("SHA-1");
				}
				catch (NoSuchAlgorithmException e) {
					// TODO Something else? This shouldn't happen.
					e.printStackTrace();
				}
			}
		}
		// Update the checksum.
		public void update(byte[] block) {
			if (usage == 255) {
				for (byte b : block) {
					summation = summation.add(b);
				}
			}
			else {
				sha1.update(block);
			}
		}
		// Do the checksum validation.
		public boolean validate(byte[] cs) {
			if (usage == 255) {
				return summation.equals(new Scalar16(cs));
			}
			else {
				byte[] hash = sha1.digest();
				return Arrays.equals(hash, cs);
			}
		}
	}

	/*
	 * DSA secret exponent x.
	 */
	protected MPI dsaX;

	/*
	 * ElGamal secret exponent x.
	 */
	protected MPI elgamalX;

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
	 * Symmetric key for decrypting private key material.
	 */
	protected Key symmetricKey;

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public SecretKeyPacket(String passPhrase, InputStream in) throws InvalidPacketException {
		super(in);
		// TODO Variable validation.

		try {
			s2kUsage = in.read();
			if (s2kUsage == 254 || s2kUsage == 255) {
				keyAlgorithm = in.read();
				s2k = String2Key.getS2K(in, passPhrase);
			}
			else if (s2kUsage == 0) {
				throw new InvalidPacketException("Plaintext secret keys not supported");
			}
			else {
				// Deprecated. TODO Decide whether to support it.
				// keyAlgorithm = in.read();
				throw new InvalidPacketException("Passphrase hash keys deprecated");
			}

				String cipherName = setKeyAlgorithm();

			in.read(initialVector);	// Size set in setKeyAlgorithm.
			Cipher cipher = getCipher(cipherName, passPhrase);
			if (version == 3) {
				readV3Secret(in, cipher);
			}
			else { // Version number was checked in the PublicKeyPacket constructor.
				readV4Secret(in, cipher);
			}
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Get the cipher instance.
	 */
	private Cipher getCipher(String cipherName, String passPhrase)
			throws InvalidPacketException {

		try {
			KeyGenerator keygen = KeyGenerator.getInstance("S2K", "CryptoKitty");
			S2KParameterSpec spec = new S2KParameterSpec(passPhrase, s2k);
			spec.setKeyAlgorithm(keyAlgorithm);
			keygen.init(spec);
			symmetricKey = keygen.generateKey();
			Cipher cipher = Cipher.getInstance(cipherName, "CryptoKitty");
			IvParameterSpec iv = new IvParameterSpec(initialVector);
			cipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);
			return cipher;
		}
		catch (UnsupportedAlgorithmException e) {
			throw new InvalidPacketException("Unsupported key algorithm");
		}
		catch (NoSuchAlgorithmException e) {
			throw new InvalidPacketException("Illegal key algorithm");
		}
		catch (NoSuchProviderException e) {
			throw new InvalidPacketException("Security provider not found");
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new InvalidPacketException("Invalid encryption paramter");
		}
		catch (NoSuchPaddingException e) {
			throw new InvalidPacketException("Invalid padding specified");
		}
		catch (InvalidKeyException e) {
			throw new InvalidPacketException("Invalid symmetric key");
		}

	}

	/*
	 * Get the symmetric key algorithm used to encrypt the private key.
	 */
	public int getKeyEncryptionAlgorithm() {
		return keyAlgorithm;
	}

	/*
	 * Get the String2Key key generator.
	 */
	public String2Key getS2K() {
		return s2k;
	}

	/*
	 * Decrypt version 3 key specs.
	 * 
	 * This version is a pain. The body of the private key material MPIs are
	 * separately encrypted, but the bitsize specifiers are not. The CFB state
	 * is reset between each encrypted field. The checksum/hash is plaintext.
	 */
	private void readV3Secret(InputStream secretIn, Cipher cipher)
			throws InvalidPacketException {

		Checksum checksum = new Checksum(s2kUsage);

		try {
			switch (pkAlgorithm) {	// From public key.
			case KeyAlgorithms.DSA:
				{
					Scalar16 precision = new Scalar16(secretIn);
					byte[] crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					byte[] clear = cipher.doFinal(crypt);
					checksum.update(clear);
					dsaX = new MPI(precision.getValue(), clear);
				}
				break;
			case KeyAlgorithms.ELGAMAL:
				{
					Scalar16 precision = new Scalar16(secretIn);
					byte[] crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					byte[] clear = cipher.doFinal(crypt);
					checksum.update(clear);
					elgamalX = new MPI(precision.getValue(), clear);
				}
				break;
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_ENCRYPT:
			case KeyAlgorithms.RSA_SIGN:
				{
					// First MPI
					Scalar16 precision = new Scalar16(secretIn);
					byte[] crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					byte[] clear = cipher.doFinal(crypt);
					checksum.update(clear);
					rsaSecretExponent = new MPI(precision.getValue(), clear);

					// Reset the cipher for the next chunk of key material
					byte[] iv = cipher.getIV();
					cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
					
					// Next MPI
					precision = new Scalar16(secretIn);
					crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					clear = cipher.doFinal(crypt);
					checksum.update(clear);
					rsaSecretPrimeP = new MPI(precision.getValue(), clear);
					
					// Reset the cipher for the next chunk of key material
					cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
					
					// Next MPI
					precision = new Scalar16(secretIn);
					crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					clear = cipher.doFinal(crypt);
					checksum.update(clear);
					rsaSecretPrimeQ = new MPI(precision.getValue(), clear);

					// Reset the cipher for the next chunk of key material
					cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
					
					// Next MPI
					precision = new Scalar16(secretIn);
					crypt = new byte[(precision.getValue() + 7) / 8];
					secretIn.read(crypt);
					clear = cipher.doFinal(crypt);
					checksum.update(clear);
					rsaU = new MPI(precision.getValue(), clear);
				}
				break;
			default:
				throw new InvalidPacketException("Illegal public key algorithm");
			}
			// The RFC says that the 2 octet checksum should not be used because of attacks
			// that can surreptitiously change the key. It is unclear what that means, but
			// since the check doesn't affect the key itself,we're going to read it and
			// calculate it.
			// Checksum/hash sent in the clear in version 3.
			byte[] cs = new byte[s2kUsage == 255 ? 2 : 20]; // checksum or sha-1 hash
			secretIn.read(cs);
			// Finally, perform the checksum/hash.
			if (!checksum.validate(cs)) {
				throw new InvalidPacketException("Checksum error");
			}
		}
		catch (IllegalBlockSizeException e) {
			throw new InvalidPacketException(e);
		}
		catch (BadPaddingException e) {
			throw new InvalidPacketException(e);
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (InvalidKeyException e) {
			throw new InvalidPacketException(e);
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Decrypt version 4 key specs.
	 * 
	 * This one is much easier. The checksum/hash is encoded with all of the
	 * secret key material so the whole thing can be decrypted as a block.
	 */
	private void readV4Secret(InputStream secretIn, Cipher cipher)
			throws InvalidPacketException {

		Checksum checksum = new Checksum(s2kUsage);

		try {
			// We want to decrypt everything left in the stream.
			byte[] crypt = new byte[secretIn.available()];
			secretIn.read(crypt);
			byte[] clear = cipher.doFinal(crypt);
			// Extract the checksum/hash and validate it before we go any farther.
			// The RFC says that the 2 octet checksum should not be used because of attacks
			// that can surreptitiously change the key. It is unclear what that means, but
			// since the check doesn't affect the key itself,we're going to read it and
			// calculate it.
			int csSize = s2kUsage == 255 ? 2 : 20;
			byte[] cs = Arrays.copyOfRange(clear, clear.length-csSize, clear.length);
			clear = Arrays.copyOf(clear, clear.length-csSize);
			checksum.update(clear);
			if (!checksum.validate(cs)) {
				throw new InvalidPacketException("Checksum error");
			}

			// Use a stream to read the key material
			ByteArrayInputStream clearIn = new ByteArrayInputStream(clear);

			switch (pkAlgorithm) {	// From public key.
			case KeyAlgorithms.DSA:
				dsaX = new MPI(clearIn);
				break;
			case KeyAlgorithms.ELGAMAL:
				elgamalX = new MPI(clearIn);
				break;
			case KeyAlgorithms.RSA:
			case KeyAlgorithms.RSA_ENCRYPT:
			case KeyAlgorithms.RSA_SIGN:
				rsaSecretExponent = new MPI(clearIn);
				rsaSecretPrimeP = new MPI(clearIn);
				rsaSecretPrimeQ = new MPI(clearIn);
				rsaU = new MPI(clearIn);
				break;
			default:
				throw new InvalidPacketException("Illegal public key algorithm");
			}
		}
		catch (IllegalBlockSizeException e) {
			throw new InvalidPacketException(e);
		}
		catch (BadPaddingException e) {
			throw new InvalidPacketException(e);
		}
		catch (IOException e) {
			throw new InvalidPacketException(e);
		}
		catch (DataException e) {
			throw new InvalidPacketException(e);
		}

	}

	/*
	 * Set up algorithm specific parameters.
	 */
	private String setKeyAlgorithm()
			throws InvalidPacketException {

		switch (keyAlgorithm) {
		case KeyAlgorithms.IDEA:
			initialVector = new byte[8];
			return "IDEA/CFB/NoPadding";
		case KeyAlgorithms.TRIPLE_DES:
			initialVector = new byte[8];
			return "DESede/CFB/NoPadding";
		case KeyAlgorithms.CAST5:
			initialVector = new byte[8];
			return "CAST5/CFB/NoPadding";
		case KeyAlgorithms.BLOWFISH:
			initialVector = new byte[8];
			return "Blowfish/CFB/NoPadding";
		case KeyAlgorithms.AES128:
			initialVector = new byte[8];
			return "AES/CFB/NoPadding";
		case KeyAlgorithms.TWOFISH:
			initialVector = new byte[16];
			return "Twofish/CFB/NoPadding";
		case KeyAlgorithms.AES192:
			initialVector = new byte[24];
			return "AES192/CFB/NoPadding";
		case KeyAlgorithms.AES256:
			initialVector = new byte[32];
			return "AES256/CFB/NoPadding";
		default:
			throw new InvalidPacketException("Illegal symmetric algorithm");
		}

	}
}
