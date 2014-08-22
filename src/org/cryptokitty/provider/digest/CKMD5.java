/**
 * 
 */
package org.cryptokitty.provider.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.data.Scalar64;


/**
 * @author Steve Brenneis
 *
 */
public class CKMD5 implements Digest {

	/*
	 * Sin function constants.
	 */
	private static final int[] T = 
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
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/**
	 * 
	 */
	public CKMD5() {
		accumulator = new ByteArrayOutputStream();
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

		byte[] context = pad(message);
		// Split the padded message into 32 bit integers
		int N = context.length / 4;
		int[] M = new int[N];
		for (int n = 0; n < N; ++n) {
			int i = n * 4;
			M[n] = Scalar32.decode(
							Arrays.copyOfRange(context, i, i + 4));
		}
		
		int A = 0x67452301;
		int B = 0xefcdab89;
		int C = 0x98badcfe;
		int D = 0x10325476;

		int[] X = new int[16];

		for (int i = 0; i < N; ++i) {

			for (int j = 0; j < 16; ++j) {
				X[j] = M[i * 16 + j];
			}

			int AA = A;
			int BB = B;
			int CC = C;
			int DD = D;

			// Round 1
			// abcd k s i
			// a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
			// [ABCD  0  7  1]
			A = round1(A, B, C, D, X[0], 7, T[1]);
			// [DABC  1 12  2]
			D = round1(D, A, B, C, X[1], 12, T[2]);
			// [CDAB  2 17  3]
			C = round1(C, D, A, B, X[2], 17, T[3]);
			// [BCDA  3 22  4]
			B = round1(B, C, D, A, X[3], 22, T[4]);
			// [ABCD  4  7  5] 
			A = round1(A, B, C, D, X[4], 7, T[5]);
			// [DABC  5 12  6]
			D = round1(D, A, B, C, X[5], 12, T[6]);
			// [CDAB  6 17  7]
			C = round1(C, D, A, B, X[6], 17, T[7]);
			// [BCDA  7 22  8]
			B = round1(B, C, D, A, X[7], 22, T[8]);
			// [ABCD  8  7  9]
			A = round1(A, B, C, D, X[8], 7, T[9]);
			// [DABC  9 12 10]
			D = round1(D, A, B, C, X[9], 12, T[10]);
			// [CDAB 10 17 11]
			C = round1(C, D, A, B, X[10], 17, T[11]);
			// [BCDA 11 22 12]
			B = round1(B, C, D, A, X[11], 22, T[12]);
			// [ABCD 12  7 13]
			A = round1(A, B, C, D, X[12], 7, T[13]);
			// [DABC 13 12 14]
			D = round1(D, A, B, C, X[13], 12, T[14]);
			// [CDAB 14 17 15]
			C = round1(C, D, A, B, X[14], 17, T[15]);
			// [BCDA 15 22 16]
			B = round1(B, C, D, A, X[15], 22, T[16]);

			// round 2
			// abcd k s i
			// a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
			// [ABCD  1  5 17]
			A = round2(A, B, C, D, X[1], 5, T[17]);
			// [DABC  6  9 18]
			D = round2(D, A, B, C, X[6], 9, T[18]);
			// [CDAB 11 14 19]
			C = round2(C, D, A, B, X[11], 14, T[19]);
			// [BCDA  0 20 20]
			B = round2(B, C, D, A, X[0], 20, T[20]);
			// [ABCD  5  5 21]
			// [DABC 10  9 22]
			// [CDAB 15 14 23]
			// [BCDA  4 20 24]
			// [ABCD  9  5 25]
			// [DABC 14  9 26]
			// [CDAB  3 14 27]
			// [BCDA  8 20 28]
			// [ABCD 13  5 29]
			// [DABC  2  9 30]
			// [CDAB  7 14 31]
			// [BCDA 12 20 32]
			
		}

		return null;

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
