package com.github.yash777;

public class HelloWorldImpl implements HelloWorld {
	 
	@Override
	public String getHelloWorldAsString(String name) {
		return "Hello World JAX-WS " + name;
	}

	@Override
	public String getSampleText() {
		return "Hello World JAX-WS  YYYY";
	}
 
}
