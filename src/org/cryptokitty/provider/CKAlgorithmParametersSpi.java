/**
 * 
 */
package org.cryptokitty.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * @author stevebrenneis
 *
 */
public class CKAlgorithmParametersSpi extends AlgorithmParametersSpi {

	/**
	 * Algorithm param spec
	 */
	protected AlgorithmParameterSpec paramSpec;
	
	/**
	 * 
	 */
	public CKAlgorithmParametersSpi() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineInit(java.security.spec.AlgorithmParameterSpec)
	 */
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {

		this.paramSpec = paramSpec;

	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineInit(byte[])
	 */
	@Override
	protected void engineInit(byte[] params) throws IOException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineInit(byte[], java.lang.String)
	 */
	@Override
	protected void engineInit(byte[] params, String format) throws IOException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineGetParameterSpec(java.lang.Class)
	 */
	@Override
	protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
			throws InvalidParameterSpecException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineGetEncoded()
	 */
	@Override
	protected byte[] engineGetEncoded() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineGetEncoded(java.lang.String)
	 */
	@Override
	protected byte[] engineGetEncoded(String format) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.AlgorithmParametersSpi#engineToString()
	 */
	@Override
	protected String engineToString() {
		// TODO Auto-generated method stub
		return null;
	}

}
