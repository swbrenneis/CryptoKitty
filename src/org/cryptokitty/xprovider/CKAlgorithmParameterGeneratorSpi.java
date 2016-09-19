/**
 * 
 */
package org.cryptokitty.xprovider;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author stevebrenneis
 *
 */
public class CKAlgorithmParameterGeneratorSpi extends AlgorithmParameterGeneratorSpi {
	
	/**
	 * Parameter size.
	 */
	protected int size;
	
	/**
	 * Secure RNG.
	 */
	protected SecureRandom random;

	/**
	 * Parameter spec.
	 */
	protected AlgorithmParameterSpec genParamSpec;
	
	/**
	 * The parameters
	 */
	protected CKAlgorithmParameters params;

	/**
	 * 
	 */
	public CKAlgorithmParameterGeneratorSpi() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParameterGeneratorSpi#engineInit(int, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(int size, SecureRandom random) {
		
		this.size = size;
		this.random = random;
		params.init(size, random);

	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParameterGeneratorSpi#engineInit(java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		
		this.genParamSpec = genParamSpec;
		this.random = random;
		params.init(genParamSpec, random);

	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParameterGeneratorSpi#engineGenerateParameters()
	 */
	@Override
	protected AlgorithmParameters engineGenerateParameters() {

		params.generate();
		return params;

	}

}
