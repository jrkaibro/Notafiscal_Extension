package com.knetapp.service;

import javax.xml.transform.Source;
import javax.xml.ws.*;

@WebServiceProvider
@ServiceMode(value = Service.Mode.PAYLOAD)
public class nfeServerPublisher implements Provider<Source> {
 
  public void main() {

		String address = "http://127.0.0.1:9876/com.knetapp.service.ServiceServer";
		Endpoint.publish(address,new nfeServiceServerImpl());
		System.out.println("Service running at " + address);

  }

public Source invoke(Source request) {
	// TODO Auto-generated method stub
	return null;
}

}