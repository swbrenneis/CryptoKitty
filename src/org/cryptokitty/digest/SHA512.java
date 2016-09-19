/**
 * 
 */
package org.cryptokitty.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.codec.Scalar128;
import org.cryptokitty.codec.Scalar64;

/**
 * @author Steve Brenneis
 *
 * SHA-512 message digest implementation
 */
public class SHA512 extends Digest {

	/*
	 * Round constants.
	 */
	private static final long[] K =
		{ 0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
		0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
		0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
		0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
		0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
		0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
		0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
		0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
		0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
		0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
		0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
		0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
		0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
		0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
		0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
		0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
		0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
		0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
		0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
		0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L };

	/*
	 * Hash constants. These are not declared final because the
	 * SHA384 class will need to change them.
	 */
	protected long H1;
	protected long H2;
	protected long H3;
	protected long H4;
	protected long H5;
	protected long H6;
	protected long H7;
	protected long H8;

	/**
	 * 
	 */
	public SHA512() {

		H1 = 0x6a09e667f3bcc908L;
		H2 = 0xbb67ae8584caa73bL;
		H3 = 0x3c6ef372fe94f82bL;
		H4 = 0xa54ff53a5f1d36f1L;
		H5 = 0x510e527fade682d1L;
		H6 = 0x9b05688c2b3e6c1fL;
		H7 = 0x1f83d9abfb41bd6bL;
		H8 = 0x5be0cd19137e2179L;

	}

	/*
	 * Ch function.
	 */
	private long Ch (long x, long y, long z) {
		return (x & y) ^ ((~x) & z);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] message) {

		// Pad the message to an even multiple of 1024 bits.
		byte[] context = pad(message);

		// Split the message up into 1024 bit chunks.
		int N = context.length / 128;
		// We need the chunk array to begin at index 1 so the indexing
		// works out below.
		byte[][] chunks = new byte[N+1][128];
		int ci = 0;
		for (int i = 1; i <= N; i++) {
			System.arraycopy(context, ci, chunks[i], 0, 128);
			ci += 128;
		}

		// Set the initial hash seeds
		long [] h1 = new long[N + 1];
		h1[0] = H1;
		long [] h2 = new long[N + 1];
		h2[0] = H2;
		long [] h3 = new long[N + 1];
		h3[0] = H3;
		long [] h4 = new long[N + 1];
		h4[0] = H4;
		long [] h5 = new long[N + 1];
		h5[0] = H5;
		long [] h6 = new long[N + 1];
		h6[0] = H6;
		long [] h7 = new long[N + 1];
		h7[0] = H7;
		long [] h8 = new long[N + 1];
		h8[0] = H8;

		// Process chunks.
		for (int i = 1; i <= N; ++i) {

			long a = h1[i-1];
			long b = h2[i-1];
			long c = h3[i-1];
			long d = h4[i-1];
			long e = h5[i-1];
			long f = h6[i-1];
			long g = h7[i-1];
			long h = h8[i-1];

			long[] w = W(chunks[i]);

			for (int j = 0; j < 80; ++j) {

				long T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
				long T2 = Sigma0(a) + Maj(a, b, c);
				
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
			d.write(Scalar64.encode(h1[N]));
			d.write(Scalar64.encode(h2[N]));
			d.write(Scalar64.encode(h3[N]));
			d.write(Scalar64.encode(h4[N]));
			d.write(Scalar64.encode(h5[N]));
			d.write(Scalar64.encode(h6[N]));
			d.write(Scalar64.encode(h7[N]));
			d.write(Scalar64.encode(h8[N]));
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
		return 64;
	}

	/*
	 * Maj function.
	 */
	private long Maj(long x, long y, long z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	/*
	 * Pad the message.
	 */
	private byte[] pad(byte[] message) {

		int bitsize = message.length * 8;
		int padbits = 896 - (bitsize % 1024);
		byte[] padding = new byte[padbits / 8];
		Arrays.fill(padding, (byte)0);
		padding[0] = (byte)0x80;
		byte[] context = new byte[message.length + padding.length + 16];
		System.arraycopy(message, 0, context, 0, message.length);
		System.arraycopy(padding, 0, context, message.length, padding.length);
		System.arraycopy(Scalar128.encode(bitsize), 0, context,
											message.length + padding.length, 16);
		return context;

	}

	/*
	 * Rotate right (shift right carry the lsb).
	 */
	private long ror(long x, long count) {
		long result = x;
		for (int i = 1; i <= count; ++i) {
			long carry = result << 63;
			result = ((result >> 1) &
						0x7fffffffffffffffL) | carry;
		}
		return result;
	}

	/*
	 * Sigma 0 function
	 */
	private long Sigma0(long x) {
		return ror(x, 28) ^ ror(x, 34) ^ ror(x, 39);
	}

	/*
	 * sigma 0 function.
	 */
	private long sigma0(long x) {
		return ror(x, 1) ^ ror(x, 8) ^ ((x >> 7) & 0x1FFFFFFFFFFFFFFL);
	}

	/*
	 * Sigma 1 function
	 */
	private long Sigma1(long x) {
		return ror(x, 14) ^ ror(x, 18) ^ ror(x, 41);
	}

	/*
	 * sigma 1 function.
	 */
	private long sigma1(long x) {
		return ror(x, 19) ^ ror(x, 61) ^ ((x >> 6) & 0x3FFFFFFFFFFFFFFL);
	}

	/*
	 * W function. Compute expanded message blocks via the SHA-512
	 * message schedule.
	 */
	private long[] W(byte[] chunk) {

		long[] w = new long[80];

		for (int j = 0; j < 16; ++j) {
			int i = j * 8;
			w[j] = Scalar64.decode(
					Arrays.copyOfRange(chunk, i, i + 8));
		}

		for (int j = 16; j < 80; ++j) {
			w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
		}
		
		return w;

	}

}
