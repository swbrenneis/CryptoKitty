/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.digest.Digest;

/**
 * @author Steve Brenneis
 *
 */
public class CKRIPEMD160 extends Digest {

	/*
	 * Added constants.
	 */
	private static final int[] K =
		{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
	private static final int[] KPrime =
		{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

	/*
	 * Message word selection constants.
	 */
	private static final int[] r =
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7,
			4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3,
			10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1,
			9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4,
			0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 };

	private static final int[] rPrime =
		{ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6,
			11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15,
			5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6,
			4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15,
			10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 };

	/*
	 * Rotate constants.
	 */
	private static final int[] s =
		{ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 
			7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 
			12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12,
			7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6,
			5,12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 
			8, 5, 6 };

	private static final int[] sPrime = 
		{ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9,
			13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 
			7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15,
			5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5,
			12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 };

	public class Int {
		private int value;
		public Int(int value) {
			this.value = value;
		}
		public int getValue() {
			return value;
		}
		public Int setValue(int value) {
			this.value = value;
			return this;
		}
	}

	/**
	 * 
	 */
	public CKRIPEMD160() {
	}

	/*
	 * RIPEMD160 is based on MD4 which is little-endian.
	 */
	private byte[] byteswap(int x) {
		byte[] answer = new byte[4];
		answer[0] = (byte)(x & 0xff);
		answer[1] = (byte)((x >> 8) & 0xff);
		answer[2] = (byte)((x >> 16) & 0xff);
		answer[3] = (byte)((x >> 24) & 0xff);
		return answer;
	}

	/*
	 * RIPEMD160 is based on MD4 which is little-endian.
	 */
	private int byteswap(byte[] x) {
		int answer = 0;
		for (int i = 3; i >= 0; --i) {
			answer = (answer << 8) | (x[i] & 0xff);
		}
		return answer;
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] message) {

		// Pad the message to an even multiple of 512 bits.
		byte[] context = pad(message);
		// Number of 16 word chunks
		int t = (context.length / 4) / 16;
		int[][] X = new int[t][16];
		int n = 0;
		for (int i = 0; i < t; ++i) {
			for (int j = 0; j < 16; ++j) {
				X[i][j]  = byteswap(Arrays.copyOfRange(context, n, n + 4));
				n += 4;
			}
		}
		 // Initial state.
		int h0 = 0x67452301;
		int h1 = 0xEFCDAB89;
		int h2 = 0x98BADCFE;
		int h3 = 0x10325476;
		int h4 = 0xC3D2E1F0;

		for (int i = 0; i < t; ++i) {

			int A = h0;
			int B = h1;
			int C = h2;
			int D = h3;
			int E = h4;

			int APrime = h0;
			int BPrime = h1;
			int CPrime = h2;
			int DPrime = h3;
			int EPrime = h4;

			int j = 0;
			for (j = 0; j < 80; ++j) {

				int T = rol((A + f(j, B, C, D) + X[i][r[j]] + K[j/16]) , s[j]) + E;
				A = E;
				E = D;
				D = rol(C, 10);
				C = B;	
				B = T;

				T = rol((APrime + f(79-j, BPrime, CPrime, DPrime) + X[i][rPrime[j]] + KPrime[j/16]), sPrime[j]) + EPrime;
	            APrime = EPrime;
	            EPrime = DPrime;
	            DPrime = rol(CPrime, 10);
	            CPrime = BPrime;
	            BPrime = T;

			}

			/* combine results */
			DPrime += C + h1;
			h1 = h2 + D + EPrime;
			h2 = h3 + E + APrime;
			h3 = h4 + A + BPrime;
			h4 = h0 + B + CPrime;
			h0 = DPrime;

		}

		ByteArrayOutputStream d = new ByteArrayOutputStream();
		
		try {
			d.write(byteswap(h0));
			d.write(byteswap(h1));
			d.write(byteswap(h2));
			d.write(byteswap(h3));
			d.write(byteswap(h4));
		}
		catch (IOException e) {
			// Nope. Silly Java inheritance problem.
			throw new RuntimeException(e);
		}

		return d.toByteArray();

	}

	/*
	 * Non-linear functions.
	 */
	private int f(int j, int x, int y, int z) {
		if (j <= 15) {
			return x ^ y ^ z;
		}
		else if (j <= 31) {
			return (x & y ) | ((~x) & z);
		}
		else if (j <= 47) {
			return (x | (~y)) ^ z;
		}
		else if (j <= 63) {
			return (x & z) | (y & (~z));
		}
		else {
			return x ^ (y | (~z));
		}
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#getBlockSize()
	 */
	@Override
	public int getBlockSize() {

		return 64;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#getDigestLength()
	 */
	@Override
	public int getDigestLength() {

		return 20;

	}

	/*
	 * Pad the message.
	 */
	private byte[] pad(byte[] in) {

		long bitsize = in.length * 8;
		long padbits = 448 - (bitsize % 512);
		byte[] padding = new byte[(int)(padbits / 8)];
		Arrays.fill(padding, (byte)0);
		padding[0] = (byte)0x80;
		byte[] context = new byte[in.length + padding.length + 8];
		System.arraycopy(in, 0, context, 0, in.length);
		System.arraycopy(padding, 0, context, in.length, padding.length);
		byte[] bitbytes = new byte[8];
		bitbytes[0] = (byte)(bitsize & 0xff);
		bitbytes[1] = (byte)((bitsize >> 8) & 0xff);
		bitbytes[2] = (byte)((bitsize >> 16) & 0xff);
		bitbytes[3] = (byte)((bitsize >> 24) & 0xff);
		bitbytes[4] = (byte)((bitsize >> 32) & 0xff);
		bitbytes[5] = (byte)((bitsize >> 40) & 0xff);
		bitbytes[6] = (byte)((bitsize >> 48) & 0xff);
		bitbytes[7] = (byte)((bitsize >> 46) & 0xff);
		System.arraycopy(bitbytes, 0, context, in.length + padding.length, 8);
		return context;

	}

	/*
	 * Rotate left (shift left carry the msb).
	 */
	private int rol(int x, int count) {
		int result = x;
		for (int i = 1; i <= count; ++i) {
			int carry = (result >> 31) & 0x01;
			result = (result << 1) | carry;
		}
		return result;
	}

}
