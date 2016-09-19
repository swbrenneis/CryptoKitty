/**
 * 
 */
package org.cryptokitty.modes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.cipher.BlockCipher;
import org.cryptokitty.codec.Scalar32;
import org.cryptokitty.codec.Scalar64;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;

/**
 * @author stevebrenneis
 *
 */
public class GCM implements AEADCipherMode {

	/**
	 * The block cipher.
	 */
	private BlockCipher cipher;

	/**
	 * Indicates the the authentication tag is appended to the ciphertext.
	 */
	private boolean appendedTag;

	/**
	 * Initial value.
	 */
	private byte[] IV;

	/**
	 * Authentication tag;
	 */
	private byte[] T;

	/**
	 * Additional authentication data;
	 */
	private byte[] A;

	/**
	 * Authentication tag size.
	 */
	private int tagSize;

	/**
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public GCM(BlockCipher cipher, boolean appendedTag) throws IllegalBlockSizeException {

		if (cipher.getBlockSize() != 16) {
			throw new IllegalBlockSizeException("Invalid GCM block cipher size");
		}
		this.cipher = cipher;
		this.appendedTag = appendedTag;
		this.tagSize = 128;

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#decrypt(byte[], byte[])
	 */
	@Override
	public byte[] decrypt(byte[] ciphertext, byte[] key)
						throws IllegalBlockSizeException, BadParameterException {

		byte[] C;
		if (appendedTag) {
			int tagLength = tagSize / 8;
			C = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - tagLength);
			T = Arrays.copyOfRange(ciphertext, ciphertext.length - tagLength,
																ciphertext.length);
		}
		else {
			C = ciphertext;
		}

		int n = C.length / 16;
		int u = C.length % 16;
		if (u == 0) {
			u = 16;
			n--;
		}

		byte[] empty = new byte[16];
		Arrays.fill(empty, (byte)0);
		byte[] H = cipher.encrypt(empty, key);

		ByteArrayOutputStream Y0 = new ByteArrayOutputStream();
		try {
			if (IV.length == 12) {
				byte[] ctr = new byte[4];
				Arrays.fill(ctr, (byte)0);
				ctr[3] = 0x01;
				Y0.write(IV);
				Y0.write(ctr);
			}
			else {
				Y0.write(GHASH(H, new byte[0], IV));
			}
		}
		catch (IOException e) {
			// Java poop. The exception is never thrown from a byte stream.
			return null;
		}

		byte[] Tp = GHASH(H, A, C);
		Tp = xor(Tp, cipher.encrypt(Y0.toByteArray(), key));
		if (T != Tp) {
			// Fail silently.
			return null;
		}
		else {
			byte[] Yi;							// Y(i)
			byte[] Yi1 = Y0.toByteArray();		// Y(i-1)
			byte[] Ci;							// C(i)
			byte[] Pi;							// C(i);

			ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
			try {
				if (C.length > 0) {
					for (int i = 1; i <= n; ++i) {
						Yi = incr(Yi1);
						int ii = (i - 1) * 16;
						Ci = Arrays.copyOfRange(C, ii, ii + 16);
						Pi = xor(Ci, cipher.encrypt(Yi, key));
						plaintext.write(Pi);
						Yi1 = Yi;
					}
					Yi = incr(Yi1);
					int cu = C.length - u;
					byte[] Cn = Arrays.copyOfRange(C, cu, cu + u);
					plaintext.write(xor(Cn, Arrays.copyOfRange(cipher.encrypt(Yi, key), 0, u)));
				}
				return plaintext.toByteArray();
			}
			catch (IOException e) {
				// Java poop. The exception is never thrown from a byte stream.
				return null;
			}
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#encrypt(byte[], byte[])
	 */
	@Override
	public byte[] encrypt(byte[] P, byte[] key)
							throws IllegalBlockSizeException, BadParameterException {

		int n = P.length / 16;
		int u = P.length % 16;
		if (u == 0) {
			u = 16;
			n--;
		}

		byte[] empty = new byte[16];
		Arrays.fill(empty, (byte)0);
		byte[] H = cipher.encrypt(empty, key);

		ByteArrayOutputStream Y0 = new ByteArrayOutputStream();
		try {
			if (IV.length == 12) {
				byte[] ctr = new byte[4];
				Arrays.fill(ctr, (byte)0);
				ctr[3] = 0x01;
				Y0.write(IV);
				Y0.write(ctr);
			}
			else {
				Y0.write(GHASH(H, new byte[0], IV));
			}
		}
		catch (IOException e) {
			// Java poop. The exception is never thrown from a byte stream.
			return null;
		}

		byte[] Yi;						// Y(i)
		byte[] Yi1 = Y0.toByteArray();	// Y(i-1)
		byte[] Pi;						// P(i)
		byte[] Ci;						// C(i)

		byte[] C = new byte[0];
		ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
		try {
			if (P.length > 0) {
				for (int i = 1; i <= n; ++i) {
					Yi = incr(Yi1);
					int ii = (i - 1) * 16;
					Pi = Arrays.copyOfRange(P, ii, ii + 16);
					Ci = xor(Pi, cipher.encrypt(Yi, key));
					ciphertext.write(Ci);
					Yi1 = Yi;
				}
				Yi = incr(Yi1);
				int pu = P.length - u;
				byte[] Pn = Arrays.copyOfRange(P, pu, pu + u);
				C = xor(Pn, Arrays.copyOfRange(cipher.encrypt(Yi, key), 0, u));
				ciphertext.write(C);
			}
		}
		catch (IOException e) {
			// Java poop. The exception is never thrown from a byte stream.
			return null;
		}

		T = GHASH(H, A, C);
		T = xor(T, cipher.encrypt(Y0.toByteArray(), key));

		return ciphertext.toByteArray();

	}

	/**
	 * 
	 * @return
	 */
	public int getTagSize() {

		return tagSize;
		
	}

	/**
	 * GHASH function. See NIST SP 800-38D, section 6.4.
	 * X must be an even multiple of 16 bytes. H is the subhash
	 * key. Yi is always 128 bits.
	 * @throws BadParameterException 
	 * @throws IOException 
	 */
	private final byte[] GHASH(final byte[] H, final byte[] A, final byte[] C)
													throws BadParameterException {

		if (H.length != 16) {
			throw new BadParameterException("Invalid GCM hash sub-key");
		}

		// Caution! A may be zero length.
		if (A == null) {
			throw new BadParameterException("Missing AEAD data");
		}
		int m = A.length / 16;
		int v = A.length % 16;
		if (v == 0) {
			v = 16;
			m--;
		}
		// Caution! C may be zero length.
		if (C == null) {
			throw new BadParameterException("Missing ciphertext");
		}
		int n = C.length / 16;
		int u = C.length % 16;
		if (u == 0) {
			u = 16;
			n--;
		}

		byte[] Xi1 = new byte[16];
		Arrays.fill(Xi1, (byte)0);		// X(i-1)
		byte[] Xi;						// X(i)
		byte[] Ai;                   // A(i)
		byte[] Ci;                   // C(i)

		@SuppressWarnings("unused")
		int i = 1; // For tracking Xi index. Debug only.
		for (int j = 0; j < m; ++j) {
			int jj = j * 16;
			Ai = Arrays.copyOfRange(A, jj, jj + 16);
			Xi = multiply(xor(Xi1, Ai), H);
			i++;
			Xi1 = Xi;
		}

		try {
			if (A.length > 0) {
				ByteArrayOutputStream Am = new ByteArrayOutputStream();
				int av = A.length - v;
				Am.write(Arrays.copyOfRange(A, av, av + v));    // A(n)
				byte[] pad = new byte[16 - v];
				Arrays.fill(pad, (byte)0);
				Am.write(pad);
				Xi = multiply(xor(Xi1, Am.toByteArray()), H);
				i++;
				Xi1 = Xi;
			}

			for (int j = 0; j < n; ++j) {
				int jj = j * 16;
				Ci = Arrays.copyOfRange(C, jj, jj + 16);
				Xi = multiply(xor(Xi1, Ci), H);
				i++;
				Xi1 = Xi;
			}

			if (C.length > 0) {
				ByteArrayOutputStream Cn = new ByteArrayOutputStream();
				int cu = C.length - u;
				Cn.write(Arrays.copyOfRange(C, cu, cu + u));    // A(n)
				byte[] pad = new byte[16 - u];
				Arrays.fill(pad, (byte)0);
				Cn.write(pad);
				Xi = multiply(xor(Xi1, Cn.toByteArray()), H);
				i++;
				Xi1 = Xi;
			}

			ByteArrayOutputStream ac = new ByteArrayOutputStream();
			ac.write(Scalar64.encode(A.length * 8));
			ac.write(Scalar64.encode(C.length * 8));
			Xi = multiply(xor(Xi1, ac.toByteArray()), H);

			return Xi;
		}
		catch (IOException e) {
			// This is Java poop. These exceptions never happen in the
			// byte output stream.
			return null;
		}

	}

	/**
	 * Galois incr function. See NIST SP 800-38D, section 6.2.
	 * Increments the rightmost s bits of X leaving the leftmost in
	 * the bit string unchanged.
	 * 
	 * @throws BadParameterException 
	 * @throws IOException 
	 */
	private final byte[] incr(final byte[] X) throws BadParameterException {

		if (X.length != 16) {
			throw new BadParameterException("Illegal GCM block size");
		}

		ByteArrayOutputStream fixed = new ByteArrayOutputStream();
		try {
			fixed.write(Arrays.copyOfRange(X, 0, 12));
			Scalar32 x = new Scalar32(Arrays.copyOfRange(X, 12, 16));
			Scalar32 inc = new Scalar32(x.getValue() + 1);
			fixed.write(inc.getEncoded());
		}
		catch (IOException e) {
			// This is Java poop. These exceptions never happen in the
			// byte output stream.
		}

		return fixed.toByteArray();

	}

	/**
	 * Galois multiplication function. See NIST SP 800-3D, Section 6.3.
	 * X, Y, and Z are 128 bits.
	 * 
	 * @param X
	 * @param Y
	 * @return
	 * @throws BadParameterException
	 */
	private final byte[] multiply(final byte[] X, final byte[] Y) throws BadParameterException {

		if (X.length != 16 || Y.length != 16) {
			throw new BadParameterException("Invalid GCM multiplicand or multiplier size");
		}

		byte[] Z = new byte[16];
		Arrays.fill(Z, (byte)0);
		byte[] V = Y;

		int[] bits = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
		for (int i = 0; i < 16; ++i) {
			for (int j = 0; j < 8; ++j) {
				if ((X[i] & (bits[7-j] & 0xff)) != 0) {
					Z = xor(Z, V);
				}
				if ((V[15] & 0x01) != 0) {
					shiftBlock(V);
					int v0 = V[0] ^ 0xe1;
					V[0] = (byte)(v0 & 0xff);
				}
				else {
					shiftBlock(V);
				}
			}
		}

		return Z;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.modes.AEADCipherMode#setAuthenticationData(byte[])
	 */
	@Override
	public void setAuthenticationData(byte[] authData) {

		A = authData;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.modes.BlockMode#setIV(byte[])
	 */
	@Override
	public void setIV(byte[] iv) {

		this.IV = iv;

	}

	/**
	 * 
	 * @param tagSize
	 */
	public void setTagSize(int tagSize) {

		this.tagSize = tagSize;

	}

	/**
	 * Shift a block right one bit.
	 * 
	 * @param block
	 */
	private final void shiftBlock(byte[] block) {

		Scalar32 be = new Scalar32(Arrays.copyOfRange(block, 12, 16));
		long value = be.getValue() & 0xffff;
	    value = value >> 1;
	    if ((block[11] & 0x01) != 0) {
	        value |= 0x80000000;
	    }
	    Scalar32 v = new Scalar32((int)value);
	    System.arraycopy(v.getEncoded(), 0, block, 12, 4);

	    value = Scalar32.decode(Arrays.copyOfRange(block, 8, 12));
	    value = (value >> 1) & 0xffff;
	    if ((block[7] & 0x01) != 0) {
	        value |= 0x80000000;
	    }
	    Scalar32 vi = new Scalar32((int)value);
	    System.arraycopy(vi.getEncoded(), 0, block, 8, 4);

	    value = Scalar32.decode(Arrays.copyOfRange(block, 4, 8));
	    value = (value >> 1) & 0xffff;
	    if ((block[3] & 0x01) != 0) {
	        value |= 0x80000000;
	    }
	    Scalar32 vii = new Scalar32((int)value);
	    System.arraycopy(vii.getEncoded(), 0, block, 4, 4);

	    value = Scalar32.decode(Arrays.copyOfRange(block, 0, 4));
	    value = (value >> 1) & 0xffff;
	    Scalar32 viii = new Scalar32((int)value);
	    System.arraycopy(viii.getEncoded(), 0, block, 0, 4);

	}

	/**
	 * Array xor function.
	 * 
	 * @param lhs
	 * @param rhs
	 * @return
	 */
	private byte[] xor(byte[] lhs, byte[] rhs) {
		
		byte[] result = new byte[lhs.length];
		for (int i = 0; i < lhs.length; ++i) {
			int x = lhs[i] ^ rhs[i];
			result[i] = (byte)(x & 0xff);
		}
		return result;

	}

}
