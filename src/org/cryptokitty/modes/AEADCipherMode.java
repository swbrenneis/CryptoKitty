/**
 * 
 */
package org.cryptokitty.modes;

/**
 * @author stevebrenneis
 *
 */
public interface AEADCipherMode extends BlockCipherMode {

	public void setAuthenticationData(byte[] authData);

}
