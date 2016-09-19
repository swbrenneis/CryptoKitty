package org.cryptokitty.provider.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import org.cryptokitty.data.Scalar32;
import org.cryptokitty.provider.digest.CKSHA224;
import org.cryptokitty.provider.digest.CKSHA256;
import org.cryptokitty.provider.digest.CKSHA384;
import org.cryptokitty.provider.digest.CKSHA512;
import org.cryptokitty.provider.digest.Digest;
import org.cryptokitty.provider.signature.RSASignature;

public final class CKRSAmgf1 {

	/***
	 * Hash function.
	 */
	private Digest digest;

	/**
	 * Provider constructor.
	protected CKRSAmgf1(String hashAlgorithm) {

		try {
			this.hash = MessageDigest.getInstance(hashAlgorithm, "CK");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Won't happen. The algorithm is verified in RSA constructor
			// and in the subsequent calling methods.
			throw new RuntimeException("Unsupported hash algorithm");
		}
	}*/

	/**
	 * Standalone constructor.
	 */
	public CKRSAmgf1(RSACipher.DigestTypes type) {

		switch (type) {
		case SHA224:
			digest = new CKSHA224();
			break;
		case SHA256:
			digest = new CKSHA256();
			break;
		case SHA384:
			digest = new CKSHA384();
			break;
		case SHA512:
			digest = new CKSHA512();
			break;
		}

	}

	/**
	 * Standalone constructor.
	 */
	public CKRSAmgf1(RSASignature.DigestTypes type) {

		switch (type) {
		case SHA224:
			digest = new CKSHA224();
			break;
		case SHA256:
			digest = new CKSHA256();
			break;
		case SHA384:
			digest = new CKSHA384();
			break;
		case SHA512:
			digest = new CKSHA512();
			break;
		}

	}

	/**
	 * Generate the mask.
	 * @param mgfSeed
	 * @param maskLen
	 * @return
	 * @throws BadPaddingException
	 */
	public byte[] generateMask(byte[] mgfSeed, int maskLen)
									throws BadPaddingException {

		int hLen = digest.getDigestLength();
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
			byte[] t = digest.digest(h);
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
