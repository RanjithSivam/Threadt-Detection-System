package com.ranjith.threatdetection.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.GregorianCalendar;

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
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.taxii.client.HttpClient;
import org.mitre.taxii.messages.xml11.ContentBlock;
import org.mitre.taxii.messages.xml11.DiscoveryRequest;
import org.mitre.taxii.messages.xml11.MessageHelper;
import org.mitre.taxii.messages.xml11.ObjectFactory;
import org.mitre.taxii.messages.xml11.PollParametersType;
import org.mitre.taxii.messages.xml11.PollRequest;
import org.mitre.taxii.messages.xml11.PollResponse;
import org.mitre.taxii.messages.xml11.ResponseTypeEnum;
import org.mitre.taxii.messages.xml11.StatusMessage;
import org.mitre.taxii.messages.xml11.TaxiiXml;
import org.mitre.taxii.messages.xml11.TaxiiXmlFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.repository.RocksRepository;

public class ThreatFetch extends Thread{
	
	Logger log = LoggerFactory.getLogger(ThreatFetch.class);
	
	private ObjectFactory factory = new ObjectFactory();
	private TaxiiXmlFactory txf = new TaxiiXmlFactory();
    private TaxiiXml taxiiXml = txf.createTaxiiXml();
    private HttpClient taxiiClient;
    private Source source;
    private RocksRepository rocksRepository;
    private final int ONE_DAY = 86400000;

    
    public ThreatFetch(Source source){
    	this.source = source;
    	initialize();
    	log.info("{} thread started....",Thread.activeCount());
    }
    
    private void initialize() {
    	HttpClientBuilder cb = HttpClientBuilder.create();
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                AuthScope.ANY,
                new UsernamePasswordCredentials(source.getUsername(), source.getPassword()));        
        cb.setDefaultCredentialsProvider(credsProvider);        
        CloseableHttpClient httpClient = cb.build();
        taxiiClient = new HttpClient(httpClient);
        rocksRepository = RocksRepository.getRocksRepository();
    }
    
    private GregorianCalendar[] getBeginEnd() {
    	GregorianCalendar begin = new GregorianCalendar();
    	begin.setTime(new Date(new Date().getTime()- ONE_DAY));
        GregorianCalendar end = new GregorianCalendar();
        end.setTime(new Date());
        
        return new GregorianCalendar[] { begin, end };
    }
    
    public void pollRequest() {
    	GregorianCalendar[] date = getBeginEnd();
    	try {
			PollRequest pollRequest = factory.createPollRequest().withMessageId(MessageHelper.generateMessageId())
					.withCollectionName(source.getFeed())
					.withExclusiveBeginTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(date[0]))
					.withInclusiveEndTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(date[1]));
			PollParametersType pollParameter = new PollParametersType();
			pollParameter.setResponseType(ResponseTypeEnum.FULL);
			pollRequest.setPollParameters(pollParameter);
			
			Object responseObject = taxiiClient.callTaxiiService(new URI(source.getUrl()), pollRequest);
			if(responseObject instanceof PollResponse) {
				
//				log.info(taxiiXml.marshalToString(responseObject,false));
				
				for(ContentBlock contentBlock : ((PollResponse) responseObject).getContentBlocks()) {
					String contentBlockString = taxiiXml.marshalToString(contentBlock,false);
					STIXPackage stixPackage = STIXPackage.fromXMLString(contentBlockString.substring(contentBlockString.indexOf("<stix:STIX_Package"), contentBlockString.lastIndexOf("</stix:STIX_Package>"))+"</stix:STIX_Package>");
					
					if(stixPackage.getObservables()!=null) {
						
						if(stixPackage.getObservables().getObservables()!=null) {
							
							for(Observable observable : stixPackage.getObservables().getObservables()) {
								
								if(observable!=null){
									
									if(observable.getObject()!=null) {
										
										if(stixPackage.getObservables().getObservables().get(0).getObject().getProperties() instanceof URIObjectType) {
											URIObjectType type =  (URIObjectType) stixPackage.getObservables().getObservables().get(0).getObject().getProperties();
											String threatUrl = type.getValue().getValue().toString().trim();
											if(threatUrl.indexOf("https://")!=-1) {
												threatUrl = threatUrl.substring("https://".length());
											}else {
												threatUrl = threatUrl.substring("http://".length());
											}
											if(threatUrl.indexOf("/")!=-1) {
												threatUrl = threatUrl.substring(0,threatUrl.indexOf("/"));
											}
											
											try {
												String threatIp = InetAddress.getByName(threatUrl).getHostAddress();
												rocksRepository.save(threatIp, observable.toXMLString());
											}catch(UnknownHostException e) {
												log.error("Can't get host addresss because {}",e.getMessage());
											}
										}
										
									}
								}
							}
						}
					}
					
					if(stixPackage.getIndicators()!=null) {
						
						if(stixPackage.getIndicators().getIndicators()!=null) {
							
							for(IndicatorBaseType indicatorBaseType: stixPackage.getIndicators().getIndicators()) {
								
								Indicator indicator = (Indicator) indicatorBaseType;
								
								if(indicator.getObservable()!=null) {
									
									if(indicator.getObservable().getObject()!=null) {
										ObjectPropertiesType type = indicator.getObservable().getObject().getProperties();
										
										if(type instanceof Address) {
											String threatUrl = ((Address) type).getAddressValue().getValue().toString();
											rocksRepository.save(threatUrl, indicator.toXMLString());
											
										}else if(type instanceof URIObjectType){
											String threatUrl = ((URIObjectType)type).getValue().getValue().toString().trim();
											if(threatUrl.indexOf("https://")!=-1) {
												threatUrl = threatUrl.substring("https://".length());
											}else {
												threatUrl = threatUrl.substring("http://".length());
											}
											if(threatUrl.indexOf("/")!=-1) {
												threatUrl = threatUrl.substring(0,threatUrl.indexOf("/"));
											}
											
											try {
												String threatIp = InetAddress.getByName(threatUrl).getHostAddress();
												rocksRepository.save(threatIp, indicator.toXMLString());
											}catch(UnknownHostException e) {
												log.error("Can't get host addresss because {}",e.getMessage());
											}
										}
									}
								}
							}
						}
					}
				}
			}else if(responseObject instanceof StatusMessage) {
				log.warn("No Poll response was found. {}",taxiiXml.marshalToString(responseObject, true));
			}
                    
		} catch (DatatypeConfigurationException e) {
			log.error(e.getMessage());
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage());
		} catch (JAXBException e) {
			log.error(e.getMessage());
		} catch (IOException e) {
			log.error(e.getMessage());
		} catch (URISyntaxException e) {
			log.error(e.getMessage());
		}
    }
    
    public void discover() {
    	DiscoveryRequest dicoveryRequest = factory.createDiscoveryRequest().withMessageId(MessageHelper.generateMessageId());
    	try {
			Object responseObject = taxiiClient.callTaxiiService(new URI(source.getUrl()), dicoveryRequest);
		} catch (JAXBException | IOException | URISyntaxException e) {
			log.error(e.getMessage());
		}
    }
    
    public void collectionManagement() {
    	
    }
    
    public void run() {
    	while(true) {
    		pollRequest();
    		try {
				Thread.sleep(ONE_DAY);
			} catch (InterruptedException e) {
				log.error(e.getMessage());
			}
    	}
    }
}
