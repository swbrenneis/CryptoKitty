/**
 * 
 */
package org.cryptokitty.random;

/**
 * @author stevebrenneis
 *
 */
public class FortunaSecureRandom extends SecureRandomWrapper implements SecureRandom {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -3455700191950379176L;

	/**
	 * Opaque pointer to the underlying C++ object.
	 */
	private long pointer;

	/**
	 * 
	 */
	public FortunaSecureRandom() {

		initialize();

	}

    /**
     * Initialize the C++ object.
     */
    private native void initialize();

	/**
	 * 
	 * @param bytes
	 */
	public native void nextBytes(byte[] bytes);

	/**
	 * 
	 * @return
	 */
	public native int nextInt();

	/**
	 * 
	 * @return
	 */
	public native long nextLong();

    public static native void setStandalone(boolean standalone);

}
