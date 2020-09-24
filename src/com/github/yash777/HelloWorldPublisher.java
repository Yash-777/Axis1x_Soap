package com.github.yash777;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.ws.Endpoint;

public class HelloWorldPublisher {
	public static void main(String[] args) {
        Endpoint.publish("http://localhost:9999/ws/hello", new HelloWorldImpl());
    }
}


/*//Service Endpoint Interface
@WebService
//@SOAPBinding(style = "RPC") // Style.RPC
interface HelloWorld2 {
  @WebMethod String getHelloWorldAsString(String name);
  @WebMethod String getSampleText();
}

@WebService(endpointInterface = "com.github.yash777.HelloWorld2")
class HelloWorldImpl2 implements HelloWorld2 {
  @Override
  public String getHelloWorldAsString(String name) {
      return "Hello World JAX-WS " + name;
  }
  @Override
  public String getSampleText() {
      return "Hello World JAX-WS  YYYY";
  }
}*/