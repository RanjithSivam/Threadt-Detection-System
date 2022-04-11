package com.ranjith.threatdetection.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.logging.Logger;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.DomainName;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.URLHistory;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.taxii.client.HttpClient;
import org.mitre.taxii.messages.xml11.CollectionInformationRequest;
import org.mitre.taxii.messages.xml11.CollectionInformationResponse;
import org.mitre.taxii.messages.xml11.CollectionRecordType;
import org.mitre.taxii.messages.xml11.ContentBlock;
import org.mitre.taxii.messages.xml11.DiscoveryRequest;
import org.mitre.taxii.messages.xml11.DiscoveryResponse;
import org.mitre.taxii.messages.xml11.MessageHelper;
import org.mitre.taxii.messages.xml11.ObjectFactory;
import org.mitre.taxii.messages.xml11.PollParametersType;
import org.mitre.taxii.messages.xml11.PollRequest;
import org.mitre.taxii.messages.xml11.PollResponse;
import org.mitre.taxii.messages.xml11.ResponseTypeEnum;
import org.mitre.taxii.messages.xml11.ServiceInstanceType;
import org.mitre.taxii.messages.xml11.ServiceTypeEnum;
import org.mitre.taxii.messages.xml11.StatusMessage;
import org.mitre.taxii.messages.xml11.TaxiiXml;
import org.mitre.taxii.messages.xml11.TaxiiXmlFactory;
import org.rocksdb.RocksDBException;

import com.ranjith.threatdetection.DefaultConstants;
import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.repository.RocksRepository;

public class ThreatFetch extends Thread{
	
	Logger log = Logger.getLogger(ThreatFetch.class.getName());
	
	private ObjectFactory factory = new ObjectFactory();
	private TaxiiXmlFactory txf = new TaxiiXmlFactory();
    private TaxiiXml taxiiXml = txf.createTaxiiXml();
    private Source source;
    private RocksRepository rocksRepository;

    
    public ThreatFetch(Source source){
    	this.source = source;
    	initialize();
    	log.info(Thread.activeCount()+ " thread started....");
    }
    
    private void initialize() {
        try {
			rocksRepository = RocksRepository.getRocksRepository();
		} catch (IOException | RocksDBException e) {
			System.out.println(e.getMessage());
		}
    }
    
    private HttpClient getClient() {
    	HttpClientBuilder cb = HttpClientBuilder.create();
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                AuthScope.ANY,
                new UsernamePasswordCredentials(source.getUsername(), source.getPassword()));        
        cb.setDefaultCredentialsProvider(credsProvider);        
        CloseableHttpClient httpClient = cb.build();
        HttpClient taxiiClient = new HttpClient(httpClient);
        return taxiiClient;
    }
    
    private GregorianCalendar[] getBeginEnd() {
    	GregorianCalendar begin = new GregorianCalendar();
    	begin.setTime(new Date(new Date().getTime()- DefaultConstants.getFETCHING_TIMING()));
        GregorianCalendar end = new GregorianCalendar();
        end.setTime(new Date());
        
        return new GregorianCalendar[] { begin, end };
    }
    
    public void pollRequest(String collectionName,String source) {
    	System.out.println(collectionName+" "+source);
    	GregorianCalendar[] date = getBeginEnd();
    	HttpClient taxiiClient = getClient();
    	try {
			PollRequest pollRequest = factory.createPollRequest().withMessageId(MessageHelper.generateMessageId())
					.withCollectionName(collectionName)
					.withExclusiveBeginTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(date[0]))
					.withInclusiveEndTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(date[1]));
			PollParametersType pollParameter = new PollParametersType();
			pollParameter.setResponseType(ResponseTypeEnum.FULL);
			pollRequest.setPollParameters(pollParameter);
			Object responseObject = taxiiClient.callTaxiiService(new URI(source), pollRequest);
//			System.out.println(taxiiXml.marshalToString(responseObject,false));
			if(responseObject instanceof PollResponse) {
				
//				log.info(taxiiXml.marshalToString(responseObject,false));
				
				for(ContentBlock contentBlock : ((PollResponse) responseObject).getContentBlocks()) {
					
					String contentBlockString = taxiiXml.marshalToString(contentBlock,false);
					
					STIXPackage stixPackage = STIXPackage.fromXMLString(contentBlockString.substring(contentBlockString.indexOf("<stix:STIX_Package"), contentBlockString.lastIndexOf("</stix:STIX_Package>"))+"</stix:STIX_Package>");
					
					if(stixPackage.getObservables()!=null) {
						
						if(stixPackage.getObservables().getObservables()!=null) {
							
							for(Observable observable : stixPackage.getObservables().getObservables()) {
								
//								System.out.println(observable.toXMLString());
								
								if(observable!=null){
									
									if(observable.getObject()!=null) {
										
										 ObjectPropertiesType objectPropertiesType = observable.getObject().getProperties();
										parser(objectPropertiesType,observable.toXMLString());
										
									}
								}
							}
						}
					}
					
					if(stixPackage.getIndicators()!=null) {
						
						if(stixPackage.getIndicators().getIndicators()!=null) {
							
							for(IndicatorBaseType indicatorBaseType: stixPackage.getIndicators().getIndicators()) {
								
								Indicator indicator = (Indicator) indicatorBaseType;
								
//								System.out.println(indicator.toXMLString());
								
								if(indicator.getObservable()!=null) {
									
//									System.out.println(indicator.getObservable().toXMLString());
									
									if(indicator.getObservable().getObject()!=null) {
										ObjectPropertiesType objectPropertiesType = indicator.getObservable().getObject().getProperties();
										parser(objectPropertiesType,indicator.toXMLString());
										
									}
								}
							}
						}
					}
				}
			}else if(responseObject instanceof StatusMessage) {
				log.info("No Poll response was found." + taxiiXml.marshalToString(responseObject, true));
			}
                    
		} catch (DatatypeConfigurationException e) {
			log.severe(e.getMessage());
		} catch (UnsupportedEncodingException e) {
			log.severe(e.getMessage());
		} catch (JAXBException e) {
			log.severe(e.getMessage());
		} catch (IOException e) {
			log.severe(e.getMessage());
		} catch (URISyntaxException e) {
			log.severe(e.getMessage());
		}
    }
    
    private void collectionManagement(String source) {
    	HttpClient taxiiClient = getClient();
    	CollectionInformationRequest CollectionInformationRequest = factory.createCollectionInformationRequest().withMessageId(MessageHelper.generateMessageId());
    	Object responseObject;
		try {
			responseObject = taxiiClient.callTaxiiService(new URI(source), CollectionInformationRequest);
//			System.out.println(taxiiXml.marshalToString(responseObject, false));
			if(responseObject instanceof CollectionInformationResponse) {
				CollectionInformationResponse collectionInformationResponse = (CollectionInformationResponse) responseObject;
				for(CollectionRecordType collectionRecordType : collectionInformationResponse.getCollections()) {
					if(collectionRecordType.isAvailable()) {
						pollRequest(collectionRecordType.getCollectionName(),collectionRecordType.getPollingServices().get(0).getAddress());
					}
				}
			}else if(responseObject instanceof StatusMessage) {
				StatusMessage statusMessage = (StatusMessage) responseObject;
				log.info(statusMessage.getMessage()+statusMessage.getInResponseTo());
			}
		} catch (JAXBException | IOException | URISyntaxException e) {
			e.printStackTrace();
		}
    	
    }
    

	public void discover() {
		HttpClient taxiiClient = getClient();
    	DiscoveryRequest dicoveryRequest = factory.createDiscoveryRequest().withMessageId(MessageHelper.generateMessageId());
    	try {
			Object responseObject = taxiiClient.callTaxiiService(new URI(source.getDicoverUrl()), dicoveryRequest);
//			System.out.println(taxiiXml.marshalToString(responseObject, false));
			if(responseObject instanceof DiscoveryResponse) {
				DiscoveryResponse dr = (DiscoveryResponse) responseObject;
				for(ServiceInstanceType serviceInstanceType: dr.getServiceInstances()) {
//					System.out.println(serviceInstanceType.getAddress());
					if(serviceInstanceType.isAvailable() && serviceInstanceType.getServiceType().equals(ServiceTypeEnum.COLLECTION_MANAGEMENT)) {
						collectionManagement(serviceInstanceType.getAddress());
					}
				}
			}else if(responseObject instanceof StatusMessage) {
				StatusMessage statusMessage = (StatusMessage) responseObject;
				log.info(statusMessage.getMessage()+statusMessage.getInResponseTo());
			}
		} catch (JAXBException | IOException | URISyntaxException e) {
			log.severe(e.getMessage());
		
		}
    }

    @Override
    public void run() {
    	while(true) {
    		discover();
    		try {
				Thread.sleep(DefaultConstants.getFETCHING_TIMING());
			} catch (InterruptedException e) {
				log.severe(e.getMessage());
			}
    	}
    }
    
    
    private void parser(ObjectPropertiesType objectPropertiesType,String message) {
    	if(objectPropertiesType instanceof Address) {
			Address address = (Address) objectPropertiesType;
			parseAddress(address, message);
		}else if(objectPropertiesType instanceof URIObjectType){
			URIObjectType type =  (URIObjectType) objectPropertiesType;
			parseURIObjectType(type,message);
		}else if(objectPropertiesType instanceof Hostname) {
			Hostname hostname = (Hostname) objectPropertiesType;
			parseHostname(hostname, message);
		}else if(objectPropertiesType instanceof SocketAddress) {
			SocketAddress socketAddress = (SocketAddress) objectPropertiesType;
			parseSocketAddress(socketAddress,message);
		}else if(objectPropertiesType instanceof DomainName) {
			DomainName domainName = (DomainName) objectPropertiesType;
			parseDomainName(domainName,message);
		}else if(objectPropertiesType instanceof URLHistory) {
			URLHistory urlHistory = (URLHistory) objectPropertiesType;
			parseDomainName(urlHistory,message);
		}
    }
    

	private void parseURIObjectType(URIObjectType type,String message) {
    	String threatUrl = type.getValue().getValue().toString().trim();
//		System.out.println(Thread.currentThread().getName()+" "+ threatUrl);
		
		try {
			String threatIp = InetAddress.getByName(new URL(threatUrl).getHost()).getHostAddress();
			rocksRepository.save(threatIp, message);
		}catch(UnknownHostException | MalformedURLException e) {
			log.info("Can't get host addresss because "+e.getMessage());
		}
    }
    
    private void parseAddress(Address address,String message) {
//		System.out.println(Thread.currentThread().getName()+" "+ threatIp);
    	try {
			String threatIp = Inet4Address.getByAddress(address.getAddressValue().getValue().toString().getBytes()).getHostAddress();
			rocksRepository.save(threatIp, message);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    }
    
    private void parseHostname(Hostname hostname,String message) {
    	try {
			String threatIp = InetAddress.getByName(hostname.getHostnameValue().getValue().toString()).getHostAddress();
			rocksRepository.save(threatIp, message);
		} catch (UnknownHostException e) {
			log.info("Can't get host addresss because "+e.getMessage());
		}
    }
    
    private void parseSocketAddress(SocketAddress socketAddress,String message) {
    	parseAddress(socketAddress.getIPAddress(),message);
    }
    
    private void parseDomainName(DomainName domainName, String message) {
		try {
			String threatIp = InetAddress.getByName(domainName.getValue().getValue().toString()).getHostAddress();
			rocksRepository.save(threatIp, message);
		}catch(UnknownHostException e) {
//			log.info("Can't get host addresss because "+e.getMessage());
		}
	}

	private void parseDomainName(URLHistory urlHistory, String message) {
		urlHistory.getURLHistoryEntries().forEach((e) -> parseHostname(e.getHostname(),message));
	}
}
