package org.cryptokitty.bootstrap;

/**
 * This class is used to bootstrap CryptoKitty in application servers
 * like Tomcat and others. The application servers use separate class
 * loaders for security reasons and the shared library can only be 
 * loaded once.
 * 
 * The following line of code should be included
 * in the constructor of one of the web applications conext listeners.
 * 
 * Class.forName("org.cryptokitty.bootstrap.CkJniBootstrapper");
 * 
 * @author stevebrenneis
 *
 */
public class CkJniBootstrapper {

	static {
		System.loadLibrary("ckjni");
	}

	public static void main(String args[]) {
		System.out.println("Loaded");
	}

}
