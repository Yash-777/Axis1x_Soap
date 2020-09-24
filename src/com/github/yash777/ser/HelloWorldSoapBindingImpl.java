/**
 * HelloWorldSoapBindingImpl.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.4 Apr 22, 2006 (06:55:48 PDT) WSDL2Java emitter.
 */

package com.github.yash777.ser;

public class HelloWorldSoapBindingImpl implements com.github.yash777.ser.HelloWorld_PortType{
    public java.lang.String getSampleText() throws java.rmi.RemoteException {
        return "Sample Text";
    }

    public java.lang.String getHelloWorldAsString(java.lang.String in0) throws java.rmi.RemoteException {
    	return "Sample Text + "+in0;
    }

}
