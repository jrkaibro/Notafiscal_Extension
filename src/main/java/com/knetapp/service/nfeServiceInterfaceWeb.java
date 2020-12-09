package com.knetapp.service;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;
 
@WebService
@SOAPBinding(style = Style.RPC)
public interface nfeServiceInterfaceWeb {
	
  @WebMethod String transmitir(String parm);		    // Enviar Nota Fiscal
  @WebMethod String cancelar(String parm);       		// Cancelar Nota Fiscal  
  @WebMethod String validar(String parm);       	    // Validar Servico
  @WebMethod String validarnf(String parm);       	    // Validar Notafiscal de Service 
  @WebMethod String upgrade(String parm);        		// Atualizar Aplicacao no Cliente   
  @WebMethod String inutilizar(String parm);     		// Inutilizacao da Nota  
  @WebMethod String cartacorrecao(String parm);  		// Carta de Correcao
  @WebMethod String manifestar(String parm);     		// Manifestacao do Destinatario
  @WebMethod String protocolar(String parm);     		// Protocolar XML já enviado

}