/**
 * 
 */
package org.cryptokitty.provider.modes;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;

/**
 * @author stevebrenneis
 *
 */
public abstract class AEADBlockMode implements BlockMode {

	/**
	 * Get authentication data
	 */
	public abstract byte[] getAuthenticationData();

	/**
	 * Set authentication data.
	 */
	public abstract void setAuthenticationData(byte[] ad);

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.modes.AEADBlockMode#setParams(byte[])
	 */
	@Override
	public void setParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
		
		if (params instanceof GCMParameterSpec) {

			setIV(((GCMParameterSpec)params).getIV());

		}
		else {
			
			throw new InvalidAlgorithmParameterException("Invalid AAD parameter");
			
		}

	}

}
