/**
 * 
 */
package org.cryptokitty.provider.modes;

/**
 * @author stevebrenneis
 *
 */
public interface AEADBlockMode extends BlockMode {

	/**
	 * Get authentication data
	 */
	byte[] getAuthenticationData();

	/**
	 * Set authentication data.
	 */
	void setAuthenticationData(byte[] ad);

}
