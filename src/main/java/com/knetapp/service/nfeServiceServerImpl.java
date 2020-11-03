package com.knetapp.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import javax.jws.WebService;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.knetapp.api.nfeApiConfig;
import com.fincatto.documentofiscal.DFAmbiente;
import com.fincatto.documentofiscal.DFModelo;
import com.fincatto.documentofiscal.DFUnidadeFederativa;
import com.fincatto.documentofiscal.nfe.NFeConfig;
import com.fincatto.documentofiscal.nfe400.classes.lote.envio.NFLoteEnvio;
import com.fincatto.documentofiscal.nfe400.classes.lote.envio.NFLoteEnvioRetornoDados;
import com.fincatto.documentofiscal.nfe400.classes.lote.envio.NFLoteIndicadorProcessamento;
import com.fincatto.documentofiscal.nfe400.classes.nota.NFNota;
import com.fincatto.documentofiscal.nfe400.classes.nota.consulta.NFNotaConsultaRetorno;
import com.fincatto.documentofiscal.nfe400.webservices.WSFacade;
import com.fincatto.documentofiscal.utils.DFPersister;
import com.fincatto.documentofiscal.validadores.StringValidador;

@WebService(endpointInterface = "com.knetapp.service.nfeServiceServerImpl")
public class nfeServiceServerImpl implements nfeServiceInterfaceWeb {
  
  Logger logger = LoggerFactory.getLogger(nfeServiceServerImpl.class);

  private nfeApiConfig sconfiguracao;
  private NFLoteIndicadorProcessamento modoprocessamento;

  private JSONObject retorno;
  private String localappdata = System.getenv("LOCALAPPDATA");
  private String appdata = System.getenv("APPDATA");
  private String osname = System.getProperty("os.name");
  private String sCadeiaCertificadoSenha;
  private String sCadeiaCertificadoCaminho;
  private String sCertificadoAlias;
  private String sCaminhoCertificado;
  private String sCertificadoSenha;
  private String sVersao;
  
  private String  sCodigoSegurancaContribuinte;
  private Integer sCodigoSegurancaContribuinteID;

  private DFUnidadeFederativa sEstado;
  private DFAmbiente sAmbiente;
  
  private NFeConfig config = new NFeConfig() { 

		private KeyStore keyStoreCertificado = null;
	    private KeyStore keyStoreCadeia = null;
		
	    @SuppressWarnings("unused")
		private PrivateKey privateKey;		
		private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
	    	    
		@Override
		public String getCertificadoSenha() {
			// TODO Auto-generated method stub
			return sCertificadoSenha;
		}
		
	    @Override
	    public String getCertificadoAlias() {
	       return sCertificadoAlias;
	    }
		
	    @Override
	    public KeyStore getCertificadoKeyStore() throws KeyStoreException {
	      
	    	if (this.keyStoreCertificado == null) {
	    		
	    		try {	
	    				this.keyStoreCertificado = KeyStore.getInstance("Windows-MY", "SunMSCAPI");  
	    				this.keyStoreCertificado.load(null, null);  
	    	                      	
	    	           for (Enumeration <String> aliases = this.keyStoreCertificado.aliases(); aliases.hasMoreElements();) {
	    	                
	    	            	String alias = aliases.nextElement();
	    	                X509Certificate cert = (X509Certificate) this.keyStoreCertificado.getCertificate(alias);  
	    	                
	    	                if (this.keyStoreCertificado.containsAlias(alias))  {
	    	                	
	    	                	if (cert.getSubjectDN().toString().contains(sCaminhoCertificado.substring(0, 8))) {
	    	                	
		    	                    System.out.println("Emitido para........: " + alias);  	    	                    
		    	                    System.out.println("SubjectDN...........: " + cert.getSubjectDN().toString());  
		    	                    System.out.println("Version.............: " + cert.getVersion());  
		    	                    System.out.println("SerialNumber........: " + cert.getSerialNumber());  
		    	                    System.out.println("SigAlgName..........: " + cert.getSigAlgName());  
		    	                    System.out.println("Valido a partir de..: " + dateFormat.format(cert.getNotBefore()));  
		    	                    System.out.println("Valido ate..........: " + dateFormat.format(cert.getNotAfter()));
		    	                    
		    	                		
		    	                    PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) this.keyStoreCertificado.getEntry(alias, new KeyStore.PasswordProtection("0407".toCharArray()));
		    	                    privateKey        = pkEntry.getPrivateKey();
		    	                    sCertificadoAlias = alias;	
		    	                    break;
	    	                	}
	    	                    
	    	                } else {  
	    	                	
	    	                	System.out.println("Alias doesn't exists : " + alias);  
	    	                }  
	    	            }  
	    	 
	    	        
					} catch (Exception e) {
						// TODO: handle exception
					}	
	    	
	    	}   
		        return this.keyStoreCertificado;
	    }
		
		@Override
		public String getCadeiaCertificadosSenha() {
			// TODO Auto-generated method stub
			return sCadeiaCertificadoSenha;
		}
		
		@Override
		public KeyStore getCadeiaCertificadosKeyStore() throws KeyStoreException {
			
			  if (this.keyStoreCadeia == null) {
		            this.keyStoreCadeia = KeyStore.getInstance("JKS");
		            try (InputStream cadeia = new FileInputStream(sCadeiaCertificadoCaminho)) {
		                this.keyStoreCadeia.load(cadeia, sCadeiaCertificadoSenha.toCharArray());
		            } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
		                this.keyStoreCadeia = null;
		                throw new KeyStoreException("Nao foi possibel montar o KeyStore com o certificado", e);
		            }
		        }
		        return this.keyStoreCadeia;
		}
		
		@Override
		public DFUnidadeFederativa getCUF() {
			// TODO Auto-generated method stub
			return sEstado;
		}
		
		@Override
		public String getVersao() {
	        return sVersao;
	    }
		
		@Override
		public DFAmbiente getAmbiente() {
	        return sAmbiente;
	    }
		
		@Override
		public String getCodigoSegurancaContribuinte() {
	        return sCodigoSegurancaContribuinte;
	    }
		
		@Override
		public Integer getCodigoSegurancaContribuinteID() {
			return sCodigoSegurancaContribuinteID;
		}
	};

  public void NfeConfigurar(String CertificadoSenha,
		  					String Cnpj,
		  					String CaminhoCadeiaCertificado,
		  					String CadeiaCertificadoSenha,
		  					String Estado,
		  					String Ambiente,
		  					String IdentificadorSegurancaContribuinte, 
		  					String CodigoSegurancaContribuinte,
		  					String Versao) 
  		{
	  
	    System.out.println("CodigoSegurancaContribuinte : " + CodigoSegurancaContribuinte);
	    System.out.println("IdentificadorSegurancaContribuinte : " + IdentificadorSegurancaContribuinte);

		sconfiguracao = new nfeApiConfig();
		
		sconfiguracao.getCertificadoKeyStore        = Cnpj;
		sconfiguracao.getCertificadoSenha 		    = CertificadoSenha;		
		
		sconfiguracao.getCadeiaCertificadosKeyStore = CaminhoCadeiaCertificado;   
		sconfiguracao.getCadeiaCertificadosSenha    = CadeiaCertificadoSenha;
		sconfiguracao.getCertificadoAlias           = null;

		sconfiguracao.DFUnidadeFederativa 		    = BuscaUnidadeFederativa(Estado);
		sconfiguracao.DFAmbiente           		    = BuscaAmbiente(Ambiente);
		
		sAmbiente 				 				    = BuscaAmbiente(Ambiente);
		sEstado   				  				    = BuscaUnidadeFederativa(Estado);
		
		sCadeiaCertificadoCaminho 				    = CaminhoCadeiaCertificado;
		sCadeiaCertificadoSenha   				    = CadeiaCertificadoSenha;
		
		sCaminhoCertificado 	  				    = Cnpj;
		sCertificadoSenha                           = CertificadoSenha;
		
		sVersao                   				    = Versao;
		sCodigoSegurancaContribuinte                = CodigoSegurancaContribuinte;
		
		try {
		  	sCodigoSegurancaContribuinteID          = Integer.valueOf(IdentificadorSegurancaContribuinte); 
	  	}
	  	catch (NumberFormatException e)
	  	{
	  		sCodigoSegurancaContribuinteID = 0;
	  	}

		
	    System.out.println("----------------------    Certificado    -------------------------");
	    System.out.println("CNPJ : " + Cnpj);
	    System.out.println("PIN  : " + CertificadoSenha);	    
	    System.out.println("---------------------- Cadeia de Certificado   -------------------");
	    System.out.println(CaminhoCadeiaCertificado);
	    System.out.println("---------------------- Alias -------------------");
	    System.out.println("---------------------- ID CSC -------------------");
	    System.out.println(sCodigoSegurancaContribuinteID);
	    System.out.println("---------------------- TOKEN -------------------");
	    System.out.println(sCodigoSegurancaContribuinte);
	    System.out.println("---------------------- ALIAS -------------------");
	    System.out.println(sconfiguracao.getCertificadoAlias);
	    System.out.println("---------------------- Ambiente / Uf / Vers�o  -------------------");
	    System.out.println(Estado);
	    System.out.println(BuscaUnidadeFederativa(Estado));
	    System.out.println(BuscaAmbiente(Ambiente));
	    System.out.println(Versao);
	    System.out.println("-------------------------------THE END ----------------------------");
	    	    
	    
	    
	}

  private DFUnidadeFederativa BuscaUnidadeFederativa(String UF) {
		
		DFUnidadeFederativa unidadefederativa;
		
		switch (UF) {		
		case "PR" :
			unidadefederativa = DFUnidadeFederativa.PR;
			break;
		case "RR":
			unidadefederativa = DFUnidadeFederativa.RR;
			break;
		case "AM":
			unidadefederativa = DFUnidadeFederativa.AM;
			break;
		case "AC":
			unidadefederativa = DFUnidadeFederativa.AC;
			break;
		case "RO":
			unidadefederativa = DFUnidadeFederativa.RO;
			break;
		case "AP":
			unidadefederativa = DFUnidadeFederativa.AP;
			break;
		case "PA":
			unidadefederativa = DFUnidadeFederativa.PA;
			break;
		case "MT":
			unidadefederativa = DFUnidadeFederativa.MT;
			break;
		case "TO":
			unidadefederativa = DFUnidadeFederativa.TO;
			break;
		case "MA":
			unidadefederativa = DFUnidadeFederativa.MA;
			break;
		case "PI":
			unidadefederativa = DFUnidadeFederativa.PI;
			break;
		case "MS":
			unidadefederativa = DFUnidadeFederativa.MS;
			break;
		case "GO":
			unidadefederativa = DFUnidadeFederativa.GO;
			break;
		case "DF":
			unidadefederativa = DFUnidadeFederativa.DF;
			break;
		case "MG":
			unidadefederativa = DFUnidadeFederativa.MG;
			break;
		case "RJ":
			unidadefederativa = DFUnidadeFederativa.RJ;
			break;
		case "SP":
			unidadefederativa = DFUnidadeFederativa.SP;
			break;
		case "SC":
			unidadefederativa = DFUnidadeFederativa.SC;
			break;
		case "RS":
			unidadefederativa = DFUnidadeFederativa.RS;
			break;
		case "ES":
			unidadefederativa = DFUnidadeFederativa.ES;
			break;
		case "BA":
			unidadefederativa = DFUnidadeFederativa.BA;
			break;
		case "RN":
			unidadefederativa = DFUnidadeFederativa.RN;
			break;
		case "CE":
			unidadefederativa = DFUnidadeFederativa.CE;
			break;
		case "AL":
			unidadefederativa = DFUnidadeFederativa.AL;
			break;
		case "PE":
			unidadefederativa = DFUnidadeFederativa.PE;
			break;
		case "PB":
			unidadefederativa = DFUnidadeFederativa.PB;
			break;
		case "SE":
			unidadefederativa = DFUnidadeFederativa.SE;
			break;
		default:
			unidadefederativa = DFUnidadeFederativa.PR;
			break;
	}
		
		return unidadefederativa;
	}
	
  private DFAmbiente BuscaAmbiente(String Ambiente) {
		
		DFAmbiente dfambiente;
		
		switch (Ambiente) {		
			case "2":
				dfambiente = DFAmbiente.HOMOLOGACAO;
				 break;
			case "1" :
				dfambiente = DFAmbiente.PRODUCAO;
				 break;
			default:
				dfambiente = DFAmbiente.HOMOLOGACAO;
				 break;
		}
		
		
		return dfambiente;
	}
	
  @SuppressWarnings("unused")
  private DFModelo BuscarModelo(String Modelo) {
		
		DFModelo modelo;
		
		//'01' '04' '55' '65' '57' '58' '67'
		
		switch (Modelo) {		
		case "01":
			 modelo = DFModelo.AVULSA;
			 break;
		case "57" :
			 modelo = DFModelo.CTE;
			 break;
		case "67" :
			 modelo = DFModelo.CTeOS;
			 break;
		case "58" :
			 modelo = DFModelo.MDFE;
			 break;
		case "65" :
			 modelo = DFModelo.NFCE;
			 break;
		case "55" :
			 modelo = DFModelo.NFE;
			 break;
		case "04" :
			 modelo = DFModelo.PRODUTOR;
			 break;
		default:
			modelo = DFModelo.NFE;
	}
		
		return modelo;
	}

  private NFLoteIndicadorProcessamento DFBuscarModoProcessamento(String ModoProcessamento) {

		if (ModoProcessamento.equals("1")) {  
			modoprocessamento = NFLoteIndicadorProcessamento.PROCESSAMENTO_SINCRONO;
		    } else {  
		    	modoprocessamento = NFLoteIndicadorProcessamento.PROCESSAMENTO_ASSINCRONO;
		    }  
		
		return modoprocessamento;
	}	
  
  @SuppressWarnings("unchecked")
  private JSONObject retorno(String licenca, String cacerts, String cnpj, String xml, String recibo, String protocolo, String motivo, Number nota, Number situacao,String logtransmissao) {
		  
	  	  JSONObject retNotafiscal = new JSONObject();
	  
		  JSONObject ret = new JSONObject();
		  
		  ret.put("Licenca", licenca);
		  ret.put("Nota", nota);
		  ret.put("XML", Base64.getEncoder().encodeToString(xml.getBytes()));
		  ret.put("Protocolo", protocolo);
		  ret.put("Recibo",recibo);
		  ret.put("Status",situacao);
		  ret.put("Motivo", motivo);
		  ret.put("Log",logtransmissao);
		  
		  retNotafiscal.put("retNotafiscal",ret);
		  
		  return retNotafiscal;
	
	  }
	  
  private String postTramitir(String trasmitir) throws Exception {
	 
	  String charset = "UTF-8"; 
	  URLConnection connection = new URL("https://beta.wvetro.com.br/wvetro/rest/NotaFiscal/prest_transmitir").openConnection();
	  connection.setDoOutput(true);
	  connection.setRequestProperty("Accept-Charset", charset);
	  connection.setRequestProperty("Content-Type", "application/json;charset=" + charset);

	  try (OutputStream output = connection.getOutputStream()) {
	    output.write(trasmitir.getBytes(charset));
	  }
	  
	  InputStream response = connection.getInputStream();
	
	  return response.toString();
	  
  }

  
  @Override
  public String transmitir(String parm) {
  		
  		 String resp = null;
  		 
  		 try {
  	  		 
  			Object obj = new JSONParser().parse(parm); 
  			JSONObject jo = (JSONObject) obj; 
  			 
  	        String notafiscal  			  = (String) jo.get("XML");
  	        Number licencaid              = (Number) jo.get("LicencaId");
  	        String uf			 		  = (String) jo.get("UF"); 	      
  	        Number nota 		 		  = (Number) jo.get("Nota");
  	        String pin 		 			  = (String) jo.get("PIN"); 
  	        String cnpj        			  = (String) jo.get("CNPJ");	      
  	        String tokencsc    		      = (String) jo.get("TokenCSC");
  	        String tokenid    			  = (String) jo.get("TokenId");
  	        String versao      		      = (String) jo.get("Versao");
  	        String cadeiacertificado      = (String) jo.get("CadeiaCertificado");
  	        String cadeiacertificadosenha = (String) jo.get("CadeiaCertificadoSenha");
  	        String ambiente    			  = (String) jo.get("Ambiente");
  	        Number processo    			  = (Number) jo.get("Processo");
  	        	      
  		    byte[] bytes = Base64.getDecoder().decode(notafiscal);
  		    String xml = new String(bytes);
  		    
  		    if (ambiente.equals("2")) {
  			   cadeiacertificado =  appdata + "\\wvetro\\cacerts\\homologacao.cacerts";
  		    } else {
  			   cadeiacertificado =  appdata + "\\wvetro\\cacerts\\producao.cacerts";
  		    }
  		    
  		    logger.info("CACERTS	 : " + cadeiacertificado);
  		 	     
  	        NfeConfigurar(pin,
  	        			  cnpj,
  	        			  cadeiacertificado,
  	        			  cadeiacertificadosenha,
  	        			  uf,
  	        			  ambiente.toString(),
  	        			  tokenid,
  	        			  tokencsc,
  	        			  versao);
  	        
  	        NFLoteIndicadorProcessamento modoprocessamento;
  			modoprocessamento = DFBuscarModoProcessamento(processo.toString());		
  			NFNota notaRecuperadaAssinada    = null;
  			
  			xml = xml.replaceAll("&lt;","<");
  			xml = xml.replaceAll("&gt;",">");
  			xml = xml.replaceAll("\\r\\n\\s+","");
  				
  			try {
  				notaRecuperadaAssinada = new DFPersister().read(NFNota.class, xml);			
  			} catch (Exception e1) {
  				e1.printStackTrace();
  			}
  			
  			NFLoteEnvioRetornoDados LoteEnvioRetornoDados;
  			
  			NFLoteEnvio lote   = new NFLoteEnvio();
  			List<NFNota> notas = new ArrayList<>();
  			
  			StringValidador.tamanho15N(nota.toString(), "ID do Lote");
  			
  			notas.add(notaRecuperadaAssinada);
  			lote.setNotas(notas);
  	        lote.setIdLote(nota.toString());   			  
  	        lote.setVersao(sVersao);
  	        lote.setIndicadorProcessamento(modoprocessamento);
  	        
  	        try {
  	        	
  	        	LoteEnvioRetornoDados = new WSFacade(config).enviaLote(lote);
				retorno = retorno(licencaid.toString(),
						cadeiacertificado,
						cnpj,
						LoteEnvioRetornoDados.getLoteAssinado().toString(),
						"",
						"",
						LoteEnvioRetornoDados.getRetorno().getMotivo(),
						nota,
						Integer.parseInt(LoteEnvioRetornoDados.getRetorno().getStatus()),
						LoteEnvioRetornoDados.getRetorno().toString()
				);
  			} catch (Exception e) {

  			  logger.info("Transmitando a receita : " + e.getMessage());



				retorno = retorno(licencaid.toString(),
									cadeiacertificado,
									cnpj,
									"",
									"",
									"",
									"",
									nota,
									Integer.parseInt("999"),
									"error:"+e.getMessage()
									);
  			}
  	        
  	        try {	
  	        	resp = postTramitir(retorno.toJSONString());
  			} catch (Exception e) {
  				logger.info("Trasmitiando ao backend : " + e.getMessage());
  			}
  			
  		} catch (Exception e) {
  			logger.info("Executando o metodo transmitir : " + e.getMessage());
  		}
  		  
  	    return resp;
	}
  
	
	@Override
  public String cancelar(String parm) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
  @SuppressWarnings("unchecked")
  @Override
  public String validar(String parm) {
		
	  JSONObject jsonobj = new JSONObject();	  
	  JSONObject ret = new JSONObject();
	  
	  ret.put("status", "Service started....");	  
	  jsonobj.put("return",ret);

	  return ret.toJSONString();
	}
	

  @Override
  public String upgrade(String parm) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
  @Override
  public String inutilizar(String parm) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
  @Override
  public String cartacorrecao(String parm) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
  @Override
  public String manifestar(String parm) {
		// TODO Auto-generated method stub
		return null;
	}

  
  @Override
  public String validarnf(String parm) {
  // TODO Auto-generated method stub
	 
	  
	  	NFNotaConsultaRetorno nfloteconsultaretorno = null ;	
		String retorno = null ;
		
		try {
		
			Object obj = new JSONParser().parse(parm); 
			JSONObject jo = (JSONObject) obj; 

			String chavenota 			  = (String) jo.get("ChaveNF");
			String notafiscal  			  = (String) jo.get("XML");
			Number licencaid              = (Number) jo.get("LicencaId");
			String uf			 		  = (String) jo.get("UF");
			Number nota 		 		  = (Number) jo.get("Nota");
			String pin 		 			  = (String) jo.get("PIN");
			String cnpj        			  = (String) jo.get("CNPJ");
			String tokencsc    		      = (String) jo.get("TokenCSC");
			String tokenid    			  = (String) jo.get("TokenId");
			String versao      		      = (String) jo.get("Versao");
			String cadeiacertificado      = (String) jo.get("CadeiaCertificado");
			String cadeiacertificadosenha = (String) jo.get("CadeiaCertificadoSenha");
			String ambiente    			  = (String) jo.get("Ambiente");
			Number processo    			  = (Number) jo.get("Processo");


			if (ambiente.equals("2")) {
				cadeiacertificado =  appdata + "\\wvetro\\cacerts\\homologacao.cacerts";
			} else {
				cadeiacertificado =  appdata + "\\wvetro\\cacerts\\producao.cacerts";
			}

			logger.info("CACERTS	 : " + cadeiacertificado);

			NfeConfigurar(pin,
					      cnpj,
					      cadeiacertificado,
					      cadeiacertificadosenha,
					      uf,
					      ambiente.toString(),
					      tokenid,
					      tokencsc,
					      versao);


			try {

				nfloteconsultaretorno = new WSFacade(config).consultaNota(chavenota);
				retorno = nfloteconsultaretorno.toString();


			} catch (Exception e) {

				logger.info("Transmitando a receita : " + e.getMessage());


			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		
		return retorno;
	  
	  
  }


}