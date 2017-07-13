/**
 * 
 */
package org.cryptokitty.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.math.BigInteger;

import org.cryptokitty.codec.Scalar32;

/**
 * @author Steve Brenneis
 *
 * SHA-256 message digest implementation.
 */
public class SHA256 extends Digest{

	/*
	 * Round constants.
	 */
	private static final int[] K =
		{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	/*
	 * Hash constants.
	 */
	protected int H1;
	protected int H2;
	protected int H3;
	protected int H4;
	protected int H5;
	protected int H6;
	protected int H7;
	protected int H8;

	/**
	 * 
	 */
	public SHA256() {

		H1 = 0x6a09e667;
		H2 = 0xbb67ae85;
		H3 = 0x3c6ef372;
		H4 = 0xa54ff53a;
		H5 = 0x510e527f;
		H6 = 0x9b05688c;
		H7 = 0x1f83d9ab;
		H8 = 0x5be0cd19;

	}

	/*
	 * Ch function.
	 */
	private int Ch (int x, int y, int z) {
		return (x & y) ^ ((~x) & z);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] in) {

		// Pad the message to an even multiple of 512 bits.
		byte[] context = pad(in);

		// Split the message up into 512 bit chunks.
		int N = context.length / 64;
		// We need the chunk array to begin at index 1 so the indexing
		// works out below.
		byte[][] chunks = new byte[N+1][64];
		int ci = 0;
		for (int i = 1; i <= N; i++) {
			System.arraycopy(context, ci, chunks[i], 0, 64);
			ci += 64;
		}

		// Set the initial hash seeds
		int [] h1 = new int[N + 1];
		h1[0] = H1;
		int [] h2 = new int[N + 1];
		h2[0] = H2;
		int [] h3 = new int[N + 1];
		h3[0] = H3;
		int [] h4 = new int[N + 1];
		h4[0] = H4;
		int [] h5 = new int[N + 1];
		h5[0] = H5;
		int [] h6 = new int[N + 1];
		h6[0] = H6;
		int [] h7 = new int[N + 1];
		h7[0] = H7;
		int [] h8 = new int[N + 1];
		h8[0] = H8;

		// Process chunks.
		for (int i = 1; i <= N; ++i) {

			int a = h1[i-1];
			int b = h2[i-1];
			int c = h3[i-1];
			int d = h4[i-1];
			int e = h5[i-1];
			int f = h6[i-1];
			int g = h7[i-1];
			int h = h8[i-1];

			int[] w = W(chunks[i]);

			for (int j = 0; j < 64; ++j) {

				int T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
				int T2 = Sigma0(a) + Maj(a, b, c);
				
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;

			}

			h1[i] = h1[i-1] + a;
			h2[i] = h2[i-1] + b;
			h3[i] = h3[i-1] + c;
			h4[i] = h4[i-1] + d;
			h5[i] = h5[i-1] + e;
			h6[i] = h6[i-1] + f;
			h7[i] = h7[i-1] + g;
			h8[i] = h8[i-1] + h;

		}

		ByteArrayOutputStream d = new ByteArrayOutputStream();
		try {
			d.write(new Scalar32((int)h1[N]).getEncoded());
			d.write(new Scalar32((int)h2[N]).getEncoded());
			d.write(new Scalar32((int)h3[N]).getEncoded());
			d.write(new Scalar32((int)h4[N]).getEncoded());
			d.write(new Scalar32((int)h5[N]).getEncoded());
			d.write(new Scalar32((int)h6[N]).getEncoded());
			d.write(new Scalar32((int)h7[N]).getEncoded());
			d.write(new Scalar32((int)h8[N]).getEncoded());
		}
		catch (IOException e) {
			// Nope.
			throw new RuntimeException(e);
		}

		return d.toByteArray();

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

		return 32;

	}

	/*
	 * Maj function.
	 */
	private int Maj(int x, int y, int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	/*
	 * Pad the message.
	 */
	private byte[] pad(byte[] in) {

		/*
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
		*/
		

	    // Message size in bits - l
	    long l = in.length * 8;

	    /*
	     * Pad the message such that k + 1 + l is congruent to
	     * 448 mod 512, where k + 1 is the padding length and l is the
	     * message length. The message is always padded with a byte
	     * value of 0x80, which is a single bit added to the end of
	     * the message.
	     */
	    ByteArrayOutputStream work = new ByteArrayOutputStream();
	    work.write(in, 0, in.length);
	    work.write((byte)0x80);
	    // 512 bits = 64 bytes. The padded message includes the 64 bit
	    // big endian representation of the message length in bits, so
	    // in order to make the message modulo 512, we add bytes until
	    // the whole message, including the length encoding is an even
	    // multiple of 64,
	    while ((work.size() + 8)  % 64 != 0) {
	        work.write(0); //pad with zeroes.
	    }
	    // Append the 64 bit encoded bit length
	    BigInteger l64 = new BigInteger(new Long(l).toString());
	    byte[] lBytes = l64.toByteArray();
	    byte[] eBytes = { 0, 0, 0, 0, 0, 0, 0, 0 };
	    System.arraycopy(lBytes, 0, eBytes, 8 - lBytes.length, lBytes.length);
	    work.write(eBytes, 0, eBytes.length);

	    return work.toByteArray();

	}

	/*
	 * Rotate right (shift right carry the lsb).
	 */
	private int ror(int x, int count) {
		int result = x;
		for (int i = 1; i <= count; ++i) {
			int carry = result << 31;
			result = ((result >> 1) & 0x7fffffff) | carry;
		}
		return result;
	}

	/*
	 * Sigma 0 function
	 */
	private int Sigma0(int x) {
		return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22);
	}

	/*
	 * sigma 0 function.
	 */
	private int sigma0(int x) {
		return ror(x, 7) ^ ror(x, 18) ^ ((x >> 3) & 0x01fffffff);
	}

	/*
	 * Sigma 1 function
	 */
	private int Sigma1(int x) {
		return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25);
	}

	/*
	 * sigma 1 function.
	 */
	private int sigma1(int x) {
		return ror(x, 17) ^ ror(x, 19) ^ ((x >> 10) & 0x3FFFFF);
	}

	/*
	 * W function. Compute expanded message blocks via the SHA-256
	 * message schedule.
	 */
	private int[] W(byte[] chunk) {

		int[] w = new int[64];

		for (int j = 0; j < 16; ++j) {
			int i = j * 4;
			w[j] = new Scalar32(Arrays.copyOfRange(chunk, i, i + 4)).getValue();
		}

		for (int j = 16; j < 64; ++j) {
			w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
		}
		
		return w;

	}

}