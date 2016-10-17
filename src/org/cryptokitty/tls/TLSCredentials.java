/**
 * 
 */
package org.cryptokitty.tls;

import org.cryptokitty.exceptions.TLSException;

/**
 * @author stevebrenneis
 *
 */
public class TLSCredentials {

	/**
	 * Format constants.
	 */
	public static final int DER = 0;
	public static final int PEM = 1;

	/**
	 * Security constants.
	 */
	public static final int DH_LOW = 1;
	public static final int DH_MEDIUM = 3;
	public static final int DH_HIGH = 4;
	public static final int DH_ULTRA = 5;

	/**
	 * Must be created via the allocate method.
	 */
	protected TLSCredentials() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Allocate a credentials object.
	 * 
	 * @return
	 */
	public static native TLSCredentials allocate();

	/**
	 * 
	 * @param crlPath Path to the X509 CRL file.
	 * @param format CRL file format. Must be one of DER or PEM.
	 * @throws TLSException
	 */
	public native void setCRLFile(String crlPath, int format) throws TLSException;

	/**
	 * Set the Diffie-Hellman key size.
	 * 
	 * @param security DH_LOW, DH_MEDIUM, DH_HIGH, or DH_ULTRA
	 */
	public native void setDiffieHellmanSecurity(int security);

	/**
	 * Set the certificate and key path.
	 * 
	 * @param certPath Path to the X509 certificate.
	 * @param keyPath Path to the X509 key file.
	 * @param format Certificate and key file format. Must be one of DER or PEM.
	 * @throws TLSException
	 */
	public native void setKeyFile(String certPath, String keyPath, int format)
																throws TLSException;

	/**
	 * 
	 * @param caPath Path to the trust (CA) file
	 * @param format CA file format. Must be one of DER or PEM.
	 * @throws TLSException
	 */
	public native void setTrustFile(String caPath, int format) throws TLSException;

}
