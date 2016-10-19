/**
 * 
 */
package org.cryptokitty.jni;

import java.net.SocketImpl;
import java.net.SocketImplFactory;

/**
 * @author stevebrenneis
 *
 */
public class BerkeleyImplFactory implements SocketImplFactory {

	/**
	 * 
	 */
	public BerkeleyImplFactory() {
	}

	/* (non-Javadoc)
	 * @see java.net.SocketImplFactory#createSocketImpl()
	 */
	@Override
	public SocketImpl createSocketImpl() {

		return new BerkeleySocketImpl();

	}

}
