/**
 * 
 */
package org.cryptokitty.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

import org.cryptokitty.keys.S2KSecretKey;
import org.cryptokitty.keys.String2Key;

/**
 * @author Steve Brenneis
 *
 * A String-to-key method key generator. Generates symmetric
 * keys from a passphrase, salt, and and optional iteration
 * count. Specified in RFC 4880. See org.cyptokitty.keys.String2Key
 * for details. Simple S2K keys are deprecated, therefore, this
 * key generator will not produce them.
 */
public class S2KKeyGenerator extends KeyGeneratorSpi {

	/*
	 * The key algorithm.
	 */
	private int algorithm;

	/*
	 * Key size in bits.
	 */
	private int keysize;

	/*
	 * String2Key instance used to generate the key material.
	 */
	private String2Key s2k;

	/**
	 * 
	 */
	public S2KKeyGenerator() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see javax.crypto.KeyGeneratorSpi#engineGenerateKey()
	 */
	@Override
	protected SecretKey engineGenerateKey() {
		if (s2k != null) {
			return new S2KSecretKey(algorithm, s2k.generateKey(keysize));
		}
		else {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see javax.crypto.KeyGeneratorSpi#engineInit(java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(SecureRandom random) {
		// This method should not be used. However, the SPI doesn't
		// specify an exception, so we'll just ignore it.
	}

	/* (non-Javadoc)
	 * @see javax.crypto.KeyGeneratorSpi#engineInit(java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		if (params instanceof S2KParameterSpec) {
			s2k = ((S2KParameterSpec)params).getS2K();
			algorithm = ((S2KParameterSpec)params).getKeyAlgorithm();
			keysize = ((S2KParameterSpec)params).getKeySize();
		}
		else {
			throw new InvalidAlgorithmParameterException("Not an S2K parameter");
		}
	}

	/* (non-Javadoc)
	 * @see javax.crypto.KeyGeneratorSpi#engineInit(int, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int keysize, SecureRandom random) {
		// This method should not be used. However, the SPI doesn't
		// specify an exception, so we'll just ignore it.
	}

}
