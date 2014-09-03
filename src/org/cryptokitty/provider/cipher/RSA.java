/**
 * 
 */
package org.cryptokitty.provider.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.IllegalMessageSizeException;
import org.cryptokitty.provider.ProviderException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;
import org.cryptokitty.provider.signature.SignatureException;

/**
 * @author Steve Brenneis
 *
 * Implementation of the RSA cipher. See RFC 3447 for details.
 * 
 * Some of the variable names and method names are a bit opaque.
 * This is to more easily relate them to the RFC. Comments are
 * provided so the function won't be a mystery.
 * 
 */
public abstract class RSA {

	/*
	 * Empty (null string) hash values.

	protected static final byte[] SHA1_EMPTY =
		{ (byte)0xda, 0x39, (byte)0xa3, (byte)0xee, 0x5e, 0x6b, 0x4b,
			0x0d, 0x32, 0x55, (byte)0xbf, (byte)0xef, (byte)0x95, 0x60,
			0x18, (byte)0x90, (byte)0xaf, (byte)0xd8, 0x07, 0x09 };

	protected static final byte[] SHA256_EMPTY = 
		{ (byte)0xe3, (byte)0xb0, (byte)0xc4, 0x42, (byte)0x98,
			(byte)0xfc, 0x1c, 0x14, (byte)0x9a, (byte)0xfb, (byte)0xf4,
			(byte)0xc8, (byte)0x99, 0x6f, (byte)0xb9, 0x24, 0x27,
			(byte)0xae, 0x41, (byte)0xe4, 0x64, (byte)0x9b, (byte)0x93,
			0x4c, (byte)0xa4, (byte)0x95, (byte)0x99, 0x1b, 0x78, 0x52,
			(byte)0xb8, 0x55 };

	protected static final byte[] SHA384_EMPTY = 
		{ 0x38, (byte)0xb0, 0x60, (byte)0xa7, 0x51, (byte)0xac, (byte)0x96,
			0x38, 0x4c, (byte)0xd9, 0x32, 0x7e, (byte)0xb1, (byte)0xb1,
			(byte)0xe3, 0x6a, 0x21, (byte)0xfd, (byte)0xb7, 0x11, 0x14,
			(byte)0xbe, 0x07, 0x43, 0x4c, 0x0c, (byte)0xc7, (byte)0xbf,
			0x63, (byte)0xf6, (byte)0xe1, (byte)0xda, 0x27, 0x4e,
			(byte)0xde, (byte)0xbf, (byte)0xe7, 0x6f, 0x65, (byte)0xfb,
			(byte)0xd5, 0x1a, (byte)0xd2, (byte)0xf1, 0x48, (byte)0x98,
			(byte)0xb9, 0x5b };

	protected static final byte[] SHA512_EMPTY = 
		{ (byte)0xcf, (byte)0x83, (byte)0xe1, 0x35, 0x7e, (byte)0xef,
			(byte)0xb8, (byte)0xbd, (byte)0xf1, 0x54, 0x28, 0x50,
			(byte)0xd6, 0x6d, (byte)0x80, 0x07, (byte)0xd6, 0x20,
			(byte)0xe4, 0x05, 0x0b, 0x57, 0x15, (byte)0xdc, (byte)0x83,
			(byte)0xf4, (byte)0xa9, 0x21, (byte)0xd3, 0x6c, (byte)0xe9,
			(byte)0xce, 0x47, (byte)0xd0, (byte)0xd1, 0x3c, 0x5d,
			(byte)0x85, (byte)0xf2, (byte)0xb0, (byte)0xff, (byte)0x83,
			0x18, (byte)0xd2, (byte)0x87, 0x7e, (byte)0xec, 0x2f, 0x63,
			(byte)0xb9, 0x31, (byte)0xbd, 0x47, 0x41, 0x7a, (byte)0x81,
			(byte)0xa5, 0x38, 0x32, 0x7a, (byte)0xf9, 0x27, (byte)0xda, 0x3e };
	 */

	/*
	 * BigInteger byte mask.
	 */
	private static final BigInteger MASK = BigInteger.valueOf(0xff);
	
	/*
	 * Mask generation function. See RFC 3447, Appendix B.2.1 for details
	 */
	protected final class MGF1 {

		/*
		 * Hash function.
		 */
		private Digest hash;
	
		/*
		 * Sole constructor.
		 */
		public MGF1(String hashAlgorithm) {
			try {
				this.hash = Digest.getInstance(hashAlgorithm);
			}
			catch (UnsupportedAlgorithmException e) {
				// Won't happen. The algorithm is verified in RSA constructor
				// and in the subsequent calling methods.
				throw new RuntimeException("Unsupported hash algorithm");
			}
		}

		/*
		 * Generate the mask.
		 */
		public byte[] generateMask(byte[] mgfSeed, int maskLen)
				throws BadParameterException {

			int hLen = hash.getDigestLength();
			if (maskLen > 0x100000000L * hLen) {
				throw new BadParameterException("Mask length out of bounds");
			}

			ByteArrayOutputStream T = new ByteArrayOutputStream();
			for (int counter = 0;
					counter < Math.ceil((double)maskLen / hLen);
						++ counter) {
				byte[] C = Scalar32.encode(counter);
				byte[] h = new byte[C.length + mgfSeed.length];
				System.arraycopy(mgfSeed, 0, h, 0, mgfSeed.length);
				System.arraycopy(C, 0, h, mgfSeed.length, 4);
				byte[] t = hash.digest(h);
				try {
					T.write(t);
				}
				catch (IOException e) {
					// TODO What do we do with this?
					// Not likely to happen
				}
			}

			return Arrays.copyOf(T.toByteArray(), maskLen);

		}

	}

	/*
	 * Public key POD
	 */
	public final class PublicKey {
		// The RSA modulus.
		public BigInteger n;
		// The RSA public exponent.
		public BigInteger e;
		// Key size in bits.
		public int bitsize;
	}

	/*
	 * Base class for private keys
	 */
	public class PrivateKey {
		// Key size in bits.
		public int bitsize;
	}

	/*
	 * Private key POD.
	 */
	public final class ModulusPrivateKey
							extends PrivateKey {
		// The RSA modulus.
		public BigInteger n;
		// The RSA private exponent.
		public BigInteger d;
	}

	/*
	 * CRT private key
	 */
	public final class CRTPrivateKey
							extends PrivateKey {
		// First prime.
		public BigInteger p;
		// Second prime.
		public BigInteger q;
		// First prime CRT exponent.
		public BigInteger dP;
		// Second prime CRT exponent.
		public BigInteger dQ;
		// CRT coefficient.
		public BigInteger qInv;
	}

	/*
	 * Hash algorithm.
	 */
	protected String hashAlgorithm;

	/*
	 * The maximum size of an input octet string for the associated
	 * hash function. This is here purely for extensibility and isn't
	 * currently practical. Java cannot create a string or array longer
	 * than 2^64 - 1 bytes;
	 */
	protected BigInteger maxHash;

	/**
	 * Default constructor. The class must be subclassed.
	 */
	protected RSA() {
	}

	/*
	 * General decryption method.
	 */
	public abstract byte[] decrypt(PrivateKey K, byte[] C)
			throws DecryptionException;

	/*
	 * General encryption method.
	 */
	public abstract byte[] encrypt(PublicKey K, byte[] C)
			throws ProviderException ;

	/*
	 * Convert an integer representation to an octet string.
	 */
	protected byte[] i2osp(BigInteger x, int xLen)
			throws BadParameterException {
		
		if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) > 0) {
			throw new BadParameterException("Integer too large");
		}

		BigInteger work = new BigInteger(x.toString());
		byte[] xBytes = new byte[xLen];
		Arrays.fill(xBytes, (byte)0x00);
		int index = xLen - 1;
		while (index >= 0) {
			xBytes[index--] = work.and(MASK).byteValue();
			work = work.shiftRight(8);
		}
		return xBytes;

	}

	/*
	 * Convert an octet string to an integer. Just using the constructor gives
	 * unreliable results, so we'll do it the hard way.
	 */
	protected BigInteger os2ip(byte[] X) {
		BigInteger bi = BigInteger.valueOf(X[0] & 0xff);
		for (int i = 1; i < X.length; ++i) {
			bi = bi.shiftLeft(8).or(BigInteger.valueOf((X[i] & 0xff)));
		}
		return bi;
	}

	/**
	 * RSA decryption primitive, modulus and exponent
	 */
	protected BigInteger rsadp(ModulusPrivateKey K, BigInteger c)
		throws DecryptionException {

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new DecryptionException();
		}

		// 2. Let m = c^d mod n.
		BigInteger m = c.modPow(K.d, K.n);

		return m;

	}

	/**
	 * RSA decryption primitive, CRT method
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param c - Ciphertext representative.
	 * 
	 * @return The plaintext representative
	 * 
	 * @throws BadParameterException if ciphertext representative is out of range
	 */
	protected BigInteger rsadp(CRTPrivateKey K, BigInteger c)
		throws DecryptionException {

		// We have to compute the modulus for the range check
		BigInteger n = K.p.multiply(K.q);

		//   1. If the ciphertext representative c is not between 0 and n - 1,
		//      output "ciphertext representative out of range" and stop.
		if (c.compareTo(BigInteger.ZERO) < 1 
				|| c.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new DecryptionException();
		}

		// i.    Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
		BigInteger m_1 = c.modPow(K.dP, K.p);
		BigInteger m_2 = c.modPow(K.dQ, K.q);

		// iii.  Let h = (m_1 - m_2) * qInv mod p.
		BigInteger h = m_1.subtract(m_2).multiply(K.qInv).mod(K.p);

		// iv.   Let m = m_2 + q * h.
		BigInteger m = K.q.multiply(h).add(m_2);

		return m;

	}

	/**
	 * RSA encryption primitive
	 * 
	 * @param m - Message representative.
	 * @param publicKey - The public key
	 * 
	 * @throws BadParameterException 
	 */
	protected BigInteger rsaep(PublicKey K, BigInteger m)
			throws IllegalMessageSizeException {

		// 1. If the message representative m is not between 0 and n - 1, output
		//  "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new IllegalMessageSizeException("Message representative out of range");
		}

		// 2. Let c = m^e mod n.
		BigInteger c = m.modPow(K.e, K.n);

		return c;

	}

	/**
	 * Signature generation primitive. Modulus and exponent method.
	 * 
	 * @param K - Private key of the form (n, d).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	protected BigInteger rsasp1(ModulusPrivateKey K, BigInteger m)
			throws IllegalMessageSizeException {

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new IllegalMessageSizeException("Message representative out of range");
		}

		// Let s = m^d mod n.
		BigInteger s = m.modPow(K.d, K.n);

		return s;

	}

	/**
	 * Signature generation primitive. CRT method.
	 * 
	 * @param K - Private key of the form (q, p, dP, dQ, qInv).
	 * @param m - Message representative.
	 * 
	 * @return The signature representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	protected BigInteger rsasp1(CRTPrivateKey K, BigInteger m)
			throws IllegalMessageSizeException {

		// We have to compute the modulus for the range check
		BigInteger n = K.p.multiply(K.q);

		//   1. If the message representative c is not between 0 and n - 1,
		//      output "message representative out of range" and stop.
		if (m.compareTo(BigInteger.ZERO) < 1 
				|| m.compareTo(n.subtract(BigInteger.ONE)) > 0) {
			throw new IllegalMessageSizeException("Message representative out of range");
		}

		// i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
		BigInteger s_1 = m.modPow(K.dP, K.p);
		BigInteger s_2 = m.modPow(K.dQ, K.q);

		// iii.  Let h = (s_1 - s_2) * qInv mod p.
		BigInteger h = s_1.subtract(s_2).multiply(K.qInv).mod(K.p);

		// iv.   Let s = s_2 + q * h.
		BigInteger s = K.q.multiply(h).add(s_2);

		return s;

	}

	/**
	 * Signature verification primitive.
	 * 
	 * @param K - Public key.
	 * @param s - Signature representative.
	 * 
	 * @return The message representative
	 * 
	 * @throws BadParameterException if message representative is out of range
	 */
	protected BigInteger rsavp1(PublicKey K, BigInteger s)
			throws SignatureException {

		// 1. If the signature representative m is not between 0 and n - 1, output
		//  "signature representative out of range" and stop.
		if (s.compareTo(BigInteger.ZERO) < 1 
				|| s.compareTo(K.n.subtract(BigInteger.ONE)) > 0) {
			throw new SignatureException();
		}

		// 2. Let m = s^e mod n.
		BigInteger m = s.modPow(K.e, K.n);

		return m;

	}

	/**
	 * Sign a message
	 * 
	 * @param K - The private key.
	 * @param M - Message to be signed.
	 * 
	 * @return The signature octet array.
	 */
	public abstract byte[] sign(PrivateKey K, byte[] M)
			throws ProviderException;

	/**
	 * Sign a message
	 * 
	 * @param K - The public key.
	 * @param M - The signed message.
	 * @param S - The signature to be verified.
	 * 
	 * @return The signature octet array.
	 */
	public abstract boolean verify(PublicKey K, byte[] M, byte[] S);

	/*
	 * Byte array bitwise exclusive or.
	 */
	protected byte[] xor(byte[] a, byte[] b)
			throws BadParameterException {

		if (a.length != b.length) {
			throw new BadParameterException("Xor byte arrays must be same length");
		}

		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; ++i) {
			result[i] = (byte)((a[i] ^ b[i]) & 0xff);
		}
		return result;
	}

}
