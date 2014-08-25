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
	 * Sin function constants. Indexed at 1.
	 */
	private static final int[] T = 
		{ 0, 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
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
		for (int i = 3; i >= 0; --i) {
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
		int N = context.length / 4;
		int[] M = new int[N];
		for (int i = 0; i < N; i++) {
			int j = i * 4;
			M[i] = byteswap(Arrays.copyOfRange(context, j, j+4));
		}

		int A = 0x67452301;
		int B = 0xefcdab89;
		int C = 0x98badcfe;
		int D = 0x10325476;

		// Process each 16 word chunk
		for (int i = 0; i < N/16; ++i) {

			int[] X = new int[16];
			for (int j = 0; j < 16; ++j) {
				X[j] = M[i*16+j];
			}

			int AA = A;
			int BB = B;
			int CC = C;
			int DD = D;

			/* Round 1. */
			/* Let [abcd k s i] denote the operation
				a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
			/* Do the following 16 operations.
				[ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
				[ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
				[ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
				[ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16] */
			A = B + rol((A + F(B, C, D) + X[0] + T[1]), 7);
			D = A + rol((D + F(A, B, C) + X[1] + T[2]), 12);
			C = D + rol((C + F(D, A, B) + X[2] + T[3]), 17);
			B = C + rol((B + F(C, D, A) + X[3] + T[4]), 22);

			A = B + rol((A + F(B, C, D) + X[4] + T[5]), 7);
			D = A + rol((D + F(A, B, C) + X[5] + T[6]), 12);
			C = D + rol((C + F(D, A, B) + X[6] + T[7]), 17);
			B = C + rol((B + F(C, D, A) + X[7] + T[8]), 22);

			A = B + rol((A + F(B, C, D) + X[8] + T[9]), 7);
			D = A + rol((D + F(A, B, C) + X[9] + T[10]), 12);
			C = D + rol((C + F(D, A, B) + X[10] + T[11]), 17);
			B = C + rol((B + F(C, D, A) + X[11] + T[12]), 22);

			A = B + rol((A + F(B, C, D) + X[12] + T[13]), 7);
			D = A + rol((D + F(A, B, C) + X[13] + T[14]), 12);
			C = D + rol((C + F(D, A, B) + X[14] + T[15]), 17);
			B = C + rol((B + F(C, D, A) + X[15] + T[16]), 22);

			/* Round 2. */
			/* Let [abcd k s i] denote the operation
				a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
			/* Do the following 16 operations.
				[ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
				[ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
				[ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
				[ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32] */
			A = B + rol((A + G(B, C, D) + X[1] + T[17]), 5);
			D = A + rol((D + G(A, B, C) + X[6] + T[18]), 9);
			C = D + rol((C + G(D, A, B) + X[11] + T[19]), 14);
			B = C + rol((B + G(C, D, A) + X[0] + T[20]), 20);

			A = B + rol((A + G(B, C, D) + X[5] + T[21]), 5);
			D = A + rol((D + G(A, B, C) + X[10] + T[22]), 9);
			C = D + rol((C + G(D, A, B) + X[15] + T[23]), 14);
			B = C + rol((B + G(C, D, A) + X[4] + T[24]), 20);

			A = B + rol((A + G(B, C, D) + X[9] + T[25]), 5);
			D = A + rol((D + G(A, B, C) + X[14] + T[26]), 9);
			C = D + rol((C + G(D, A, B) + X[3] + T[27]), 14);
			B = C + rol((B + G(C, D, A) + X[8] + T[28]), 20);

			A = B + rol((A + G(B, C, D) + X[13] + T[29]), 5);
			D = A + rol((D + G(A, B, C) + X[2] + T[30]), 9);
			C = D + rol((C + G(D, A, B) + X[7] + T[31]), 14);
			B = C + rol((B + G(C, D, A) + X[12] + T[32]), 20);

			/* Round 3. */
			/* Let [abcd k s t] denote the operation
				a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
			/* Do the following 16 operations.
				[ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
				[ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
				[ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
				[ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48] */
			A = B + rol((A + H(B, C, D) + X[5] + T[33]), 4);
			D = A + rol((D + H(A, B, C) + X[8] + T[34]), 11);
			C = D + rol((C + H(D, A, B) + X[11] + T[35]), 16);
			B = C + rol((B + H(C, D, A) + X[14] + T[36]), 23);

			A = B + rol((A + H(B, C, D) + X[1] + T[37]), 4);
			D = A + rol((D + H(A, B, C) + X[4] + T[38]), 11);
			C = D + rol((C + H(D, A, B) + X[7] + T[39]), 16);
			B = C + rol((B + H(C, D, A) + X[10] + T[40]), 23);

			A = B + rol((A + H(B, C, D) + X[13] + T[41]), 4);
			D = A + rol((D + H(A, B, C) + X[0] + T[42]), 11);
			C = D + rol((C + H(D, A, B) + X[3] + T[43]), 16);
			B = C + rol((B + H(C, D, A) + X[6] + T[44]), 23);

			A = B + rol((A + H(B, C, D) + X[9] + T[45]), 4);
			D = A + rol((D + H(A, B, C) + X[12] + T[46]), 11);
			C = D + rol((C + H(D, A, B) + X[15] + T[47]), 16);
			B = C + rol((B + H(C, D, A) + X[2] + T[48]), 23);

			/* Round 4. */
			/* Let [abcd k s t] denote the operation
				a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
			/* Do the following 16 operations.
				[ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
				[ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
				[ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
				[ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64] */
			A = B + rol((A + I(B, C, D) + X[0] + T[49]), 6);
			D = A + rol((D + I(A, B, C) + X[7] + T[50]), 10);
			C = D + rol((C + I(D, A, B) + X[14] + T[51]), 15);
			B = C + rol((B + I(C, D, A) + X[5] + T[52]), 21);

			A = B + rol((A + I(B, C, D) + X[12] + T[53]), 6);
			D = A + rol((D + I(A, B, C) + X[3] + T[54]), 10);
			C = D + rol((C + I(D, A, B) + X[10] + T[55]), 15);
			B = C + rol((B + I(C, D, A) + X[1] + T[56]), 21);

			A = B + rol((A + I(B, C, D) + X[8] + T[57]), 6);
			D = A + rol((D + I(A, B, C) + X[15] + T[58]), 10);
			C = D + rol((C + I(D, A, B) + X[6] + T[59]), 15);
			B = C + rol((B + I(C, D, A) + X[13] + T[60]), 21);

			A = B + rol((A + I(B, C, D) + X[4] + T[61]), 6);
			D = A + rol((D + I(A, B, C) + X[11] + T[62]), 10);
			C = D + rol((C + I(D, A, B) + X[2] + T[63]), 15);
			B = C + rol((B + I(C, D, A) + X[9] + T[64]), 21);

			// Per chunk sum.
			A = A + AA;
			B = B + BB;
			C = C + CC;
			D = D + DD;

		}

		ByteArrayOutputStream d = new ByteArrayOutputStream();
		
		try {
			// For no good reason, MD5 is little-endian.
			d.write(byteswap(A));
			d.write(byteswap(B));
			d.write(byteswap(C));
			d.write(byteswap(D));
		}
		catch (IOException e) {
			// Nope. Silly Java inheritance problem.
			throw new RuntimeException(e);
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
