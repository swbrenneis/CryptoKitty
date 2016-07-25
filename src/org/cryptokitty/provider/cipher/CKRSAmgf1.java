package org.cryptokitty.provider.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import org.cryptokitty.data.Scalar32;

public final class CKRSAmgf1 {

	/*
	 * Hash function.
	 */
	private MessageDigest hash;

	/*
	 * Sole constructor.
	 */
	public CKRSAmgf1(String hashAlgorithm) {

		try {
			this.hash = MessageDigest.getInstance(hashAlgorithm, "CK");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Won't happen. The algorithm is verified in RSA constructor
			// and in the subsequent calling methods.
			throw new RuntimeException("Unsupported hash algorithm");
		}
	}

	/*
	 * Generate the mask.
	 */
	public byte[] generateMask(byte[] mgfSeed, int maskLen)
									throws BadPaddingException {

		int hLen = hash.getDigestLength();
		if (maskLen > 0x100000000L * hLen) {
			throw new BadPaddingException("Bad padding");
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
