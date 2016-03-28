package org.cryptokitty.provider.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;

public final class PSSmgf1 {

	/*
	 * Hash function.
	 */
	private Digest hash;

	/*
	 * Sole constructor.
	 */
	public PSSmgf1(String hashAlgorithm) {
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
