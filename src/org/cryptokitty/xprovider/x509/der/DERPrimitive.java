/**
 * 
 */
package org.cryptokitty.xprovider.x509.der;

/**
 * @author Steve Brenneis
 *
 */
public interface DERPrimitive <T> extends DERType{

	/*
	 * Return the typed value.
	 */
	public T getValue();

}
