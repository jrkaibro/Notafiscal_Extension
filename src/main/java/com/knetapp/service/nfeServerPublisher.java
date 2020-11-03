package com.knetapp.service;

import javax.xml.transform.Source;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Provider;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceProvider;

@WebServiceProvider
@ServiceMode(value = Service.Mode.PAYLOAD)
public class nfeServerPublisher implements Provider<Source> {
 
  public void main() {
	  
	  Thread thread = new Thread("wvetroThread") {
		  
	      public void run(){
	    	
    	    String address = "http://127.0.0.1:9876/com.knetapp.service.ServiceServer";
    	    Endpoint.publish(address,new nfeServiceServerImpl());
    	    System.out.println("Service running at " + address);    	  
	        System.out.println("Run by: "+ getId() + " : " + getName());
	      }
	   };

	   thread.start();
	   
  }

public Source invoke(Source request) {
	// TODO Auto-generated method stub
	return null;
}
  
}