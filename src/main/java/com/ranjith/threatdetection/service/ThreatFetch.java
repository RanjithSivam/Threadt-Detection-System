package com.ranjith.threatdetection.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
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

import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.repository.RocksRepository;

public class ThreatFetch {
	
	private ObjectFactory factory = new ObjectFactory();
	private TaxiiXmlFactory txf = new TaxiiXmlFactory();
    private TaxiiXml taxiiXml = txf.createTaxiiXml();
    private HttpClient taxiiClient;
    private Source source;
    private RocksRepository rocksRepository;
    
    public ThreatFetch(Source source){
    	this.source = source;
    	initialize();
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
    	begin.setTime(new Date(new Date().getTime()- 1000 * 60 * 60 * 24));
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
				for(ContentBlock contentBlock : ((PollResponse) responseObject).getContentBlocks()) {
					String contentBlockString = taxiiXml.marshalToString(contentBlock,false);
					STIXPackage stixPackage = STIXPackage.fromXMLString(contentBlockString.substring(contentBlockString.indexOf("<stix:STIX_Package"), contentBlockString.lastIndexOf("</stix:STIX_Package>"))+"</stix:STIX_Package>");

					if(stixPackage.getObservables()!=null) {
						
						if(stixPackage.getObservables().getObservables()!=null) {
							
							for(Observable observable : stixPackage.getObservables().getObservables()) {
								
								if(observable!=null){
									
									if(observable.getObject()!=null) {
										
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
										
										String threatIp = InetAddress.getByName(threatUrl).getHostAddress();
										rocksRepository.save(threatIp, observable.toXMLString());
										
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
											System.out.println(threatUrl);
										}
									}
								}
							}
						}
					}
				}
			}else if(responseObject instanceof StatusMessage) {
				System.out.println(responseObject);
			}
                    
		} catch (DatatypeConfigurationException e) {
			System.out.println(e);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void discover() {
    	DiscoveryRequest dicoveryRequest = factory.createDiscoveryRequest().withMessageId(MessageHelper.generateMessageId());
    	try {
			Object responseObject = taxiiClient.callTaxiiService(new URI(source.getUrl()), dicoveryRequest);
			System.out.println(taxiiXml.marshalToString(responseObject,true));
		} catch (JAXBException | IOException | URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void collectionManagement() {
    	
    }
}
