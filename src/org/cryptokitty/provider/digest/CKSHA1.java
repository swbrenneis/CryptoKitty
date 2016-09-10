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
public class CKSHA1 extends Digest {

	/*
	 * Initial hash state.
	 */
	private static final int H1 = 0x67452301;
	private static final int H2 = 0xefcdab89;
	private static final int H3 = 0x98badcfe;
	private static final int H4 = 0x10325476;
	private static final int H5 = 0xc3d2e1f0;

	/*
	 * Round constant.
	 */
	private static final int[] K =
				{ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
	/**
	 * 
	 */
	public CKSHA1() {
	}

	/*
	 * Ch function.
	 */
	private int Ch (int x, int y, int z) {
		int r = (x & y) ^ ((~x) & z);
		return r;
	}

	/*
	 * Round function.
	 */
	private int f(int x, int y, int z, int t){

		if (t <= 19) {
			return Ch(x, y, z);
		}
		else if (t <= 39) {
			return Parity(x, y, z);
		}
		else if (t <= 59) {
			return Maj(x, y, z);
		}
		else {
			return Parity(x, y, z);
		}

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] message) {

		// Pad the message to an even multiple of 512 bits.
		byte[] context = pad(message);

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

		// Process the chunks.
		for (int i = 1; i <= N; ++i) {

			int[] w = W(chunks[i]);
			
			int a = h1[i-1];
			int b = h2[i-1];
			int c = h3[i-1];
			int d = h4[i-1];
			int e = h5[i-1];

			for (int t = 0; t < 80; ++t) {

				int k;
				if (t <= 19) {
					k = K[0];
				}
				else if (t <= 39) {
					k = K[1];
				}
				else if (t <= 59) {
					k = K[2];
				}
				else {
					k = K[3];
				}
				
				int T = rol(a, 5) + f(b, c, d, t) + e + k + w[t];
				e = d;
				d = c;
				c = rol(b, 30);
				b = a;
				a = T;

			}

			h1[i] = h1[i-1] + a;
			h2[i] = h2[i-1] + b;
			h3[i] = h3[i-1] + c;
			h4[i] = h4[i-1] + d;
			h5[i] = h5[i-1] + e;

		}

		ByteArrayOutputStream d = new ByteArrayOutputStream();
		try {
			d.write(Scalar32.encode((int)h1[N]));
			d.write(Scalar32.encode((int)h2[N]));
			d.write(Scalar32.encode((int)h3[N]));
			d.write(Scalar32.encode((int)h4[N]));
			d.write(Scalar32.encode((int)h5[N]));
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
		return 20;
	}

	/*
	 * Maj function.
	 */
	private int Maj(int x, int y, int z) {
		int r = (x & y) ^ (x & z) ^ (y & z);
		return r;
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
	 * Parity function.
	 */
	private int Parity(int x, int y, int z) {
		return x ^ y ^ z;
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
	 * W function. Compute expanded message blocks via the SHA-1
	 * message schedule.
	 */
	private int[] W(byte[] chunk) {

		int[] w = new int[80];

		for (int t = 0; t < 16; ++t) {
			int i = t * 4;
			w[t] = Scalar32.decode(
					Arrays.copyOfRange(chunk, i, i + 4));
		}

		for (int t = 16; t < 80; ++t) {
			w[t] = rol((w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]), 1);
		}
		
		return w;

	}

}
