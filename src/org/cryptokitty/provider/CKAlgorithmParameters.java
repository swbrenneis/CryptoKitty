/**
 * 
 */
package org.cryptokitty.provider;

import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author stevebrenneis
 *
 */
public abstract class CKAlgorithmParameters extends AlgorithmParameters {

	/**
	 * @param paramSpi
	 * @param provider
	 * @param algorithm
	 */
	public CKAlgorithmParameters(AlgorithmParametersSpi paramSpi, Provider provider, String algorithm) {
		super(paramSpi, provider, algorithm);
		// TODO Auto-generated constructor stub
	}

	public abstract void generate();

	public abstract void init(int size, SecureRandom random);

	public abstract void init(AlgorithmParameterSpec spec, SecureRandom random)
												throws InvalidAlgorithmParameterException;

}
