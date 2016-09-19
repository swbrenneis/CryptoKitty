/**
 * 
 */
package org.cryptokitty.modes;

/**
 * @author stevebrenneis
 *
 */
public interface AEADCipherMode extends BlockMode {

	public void setAuthenticationData(byte[] authData);

}
