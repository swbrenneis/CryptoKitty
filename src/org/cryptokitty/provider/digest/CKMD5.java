/**
 * 
 */
package org.cryptokitty.provider.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.data.Scalar64;


/**
 * @author Steve Brenneis
 *
 */
public class CKMD5 implements Digest {

	/*
	 * Sin function constants.
	 */
	private static final int[] K = 
		{ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

	/*
	 * Per round shift constants
	 */
	private static final int[] s = 
		{ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };


	/*
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/**
	 * 
	 */
	public CKMD5() {
		accumulator = new ByteArrayOutputStream();
	}

	/*
	 * MD5 is little-endian. Sigh.
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
	 * MD5 is little-endian. Sigh.
	 */
	private int byteswap(byte[] x) {
		int answer = 0;
		for (int i = 3; i <= 0; --i) {
			answer = (answer << 8) | (x[i] & 0xff);
		}
		return answer;
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#digest()
	 */
	@Override
	public byte[] digest() {
		return digest(accumulator.toByteArray());
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#digest(byte[])
	 */
	@Override
	public byte[] digest(byte[] message) {

		// Pad the message to an even multiple of 512 bits.
		byte[] context = pad(message);
		// Process each 512 bit chunk.
		int N = context.length / 64;
		byte[][] chunks = new byte[N][64];
		for (int i = 0; i < N; ++i) {
			int j = i * 64;
			System.arraycopy(context, j, chunks[i], 0, 64);
		}

		int A0 = 0x67452301;
		int B0 = 0xefcdab89;
		int C0 = 0x98badcfe;
		int D0 = 0x10325476;

		// Process each 512 byte chunk
		for (int n = 0; n < N; ++n) {

			// Split the padded message into 32 bit (little-endian) integers
			int[] M = new int[16];
			for (int i = 0; i < 16; ++i) {
				int j = i * 4;
				M[i] = byteswap(Arrays.copyOfRange(chunks[n], j, j + 4));
			}
			
			int A = A0;
			int B = B0;
			int C = C0;
			int D = D0;

			// Rounds
			int F;
			int g;
			for (int i = 0; i < 64; ++i) {

				if (i <= 15) {
					F = (B & C) | ((~B) & D);
					g = i;
				}
				else if (i <= 31) {
					F = (D & B) | ((~D) & C);
					g = (5 * i + 1) % 16;
				}
				else if (i <= 47) {
					F = B ^ C ^ D;
					g = (3 * i + 5) % 16;
				}
				else {
					F = C ^ (B | (~D));
					g = (7 * i) % 16;
				}

				int dTemp = D;
				D = C;
				C = B;
				B = B + rol((A + F + K[i] + M[g]), s[i]);
				A = dTemp;

			}

			// Per chunk sum.
			A0 = A0 + A;
			B0 = B0 + B;
			C0 = C0 + C;
			D0 = D0 + D;

		}

		ByteArrayOutputStream d = new ByteArrayOutputStream();
		
		try {
			// For no good reason, MD5 is little-endian.
			d.write(byteswap(A0));
			d.write(byteswap(B0));
			d.write(byteswap(C0));
			d.write(byteswap(D0));
		}
		catch (IOException e) {
			// Nope.
		}

		return d.toByteArray();

	}

	/*
	 * Round function.
	 */
	private int F(int x, int y, int z) {
		return (x & y) |  ((~x) & z);
	}

	/*
	 * Round function
	 */
	private int G(int x, int y, int z) {
		return (x & z) | (y & (~z));
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		// TODO Auto-generated method stub
		return 16;
	}

	/*
	 * Round function.
	 */
	private int H(int x, int y, int z) {
		return x ^ y ^ z;
	}

	/*
	 * Round function.
	 */
	private int I(int x, int y, int z) {
		return y ^ (x | (~z));
	}

	/*
	 * Pad the message.
	 */
	private byte[] pad(byte[] in) {

		int bitsize = in.length * 8;
		int padbits = 448 - (bitsize % 512);
		byte[] padding = new byte[padbits / 8];
		Arrays.fill(padding, (byte)0);
		padding[0] = (byte)0x80;
		byte[] context = new byte[in.length + padding.length + 8];
		System.arraycopy(in, 0, context, 0, in.length);
		System.arraycopy(padding, 0, context, in.length, padding.length);
		System.arraycopy(Scalar64.encode(bitsize), 0, context,
											in.length + padding.length, 8);
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

	/*
	 * Round 1.
	 */
	private int round1(int a, int b, int c, int d, int k, int s, int i) {
		return b + rol((a + F(b, c, d) + k + i), s);
	}

	/*
	 * Round 2
	 */
	private int round2(int a, int b, int c, int d, int k, int s, int i) {
		return b + rol((a + G(b, c, d) + k + i), s);
	}

	/*
	 * Round 3
	 */
	private int round3(int a, int b, int c, int d, int k, int s, int i) {
		return b + rol((a + H(b, c, d) + k + i), s);
	}

	/*
	 * Round 4
	 */
	private int round4(int a, int b, int c, int d, int k, int s, int i) {
		return b + rol((a + I(b, c, d) + k + i), s);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte)
	 */
	@Override
	public void update(byte message) {
		accumulator.write(message);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte[])
	 */
	@Override
	public void update(byte[] message) {
		try {
			accumulator.write(message);
		}
		catch (IOException e) {
			// Meh.
		}
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte[], int, int)
	 */
	@Override
	public void update(byte[] message, int offset, int length) {
		accumulator.write(message, offset, length);
	}

}
