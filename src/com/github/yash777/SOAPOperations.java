package com.github.yash777;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

// https://www.soapui.org/docs/soapui-projects/ws-security/
@SuppressWarnings({"deprecation", "restriction"})
public class SOAPOperations {
	// https://github.com/mulderbaba/webservices-osgi/blob/7090b58bd4cdf5fab4af14d54cb20bb45c074de2/com/sun/xml/wss/impl/MessageConstants.java
	static class MessageConstants {
		public static final String 
		SOAP_1_1_NS = "http://schemas.xmlsoap.org/soap/envelope/",
	    SOAP_1_2_NS = "http://www.w3.org/2003/05/soap-envelope",
	    
		WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
	    WSSE_PREFIX = "wsse",
	    
	    WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	    WSU_PREFIX = "wsu",
	    
	    DSIG_NS = "http://www.w3.org/2001/10/xml-exc-c14n#", // javax.xml.crypto.dsig.XMLSignature.XMLNS, Constants.SignatureSpecNS
		DSIG_PREFIX = "ds",
		
	    WSS_SPEC_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0",
	    BASE64_ENCODING_NS = WSS_SPEC_NS + "#Base64Binary",
	    
	    X509_TOKEN_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0",
	    X509_NS = X509_TOKEN_NS + "#X509", X509v1_NS = X509_TOKEN_NS + "#X509v1", X509v3_NS = X509_TOKEN_NS + "#X509v3",
	    X509SubjectKeyIdentifier_NS = X509_TOKEN_NS + "#X509SubjectKeyIdentifier",
	    
		TRANSFORM_C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#" // Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS
	    ;
	}
	/*
Message Security
Each XML message should contain information in the header about the certificate used for signing the message. 
There are two fields required: the Issuing Body (CA) and the Serial Number of the certificate. The layout of this header 
is fixed. With this rule we are following official standards, a description of the standard can be found here
http://www.w3.org/TR/xmldsig-core/#sec-CoreSyntax (under reference [signing1]).


Only the payload of the message is signed (everything within the SOAP body), using the following specs:
 SignatureMethod – RSAwithSHA256          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
 CanonicalizationMethod – xml-exc-c14n#   <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
 DigestMethod – xmlenc#sha256             <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
 KeyInfo/X509Data – X509SKI (X509IssuerSerial has been deprecated)
	 */
	static final String 
	signatureMethod_Algo =  XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, // SignatureMethod.RSA_SHA1, org.jcp.xml.dsig.internal.dom.DOMSignatureMethod.RSA_SHA256,
	canonicalizationMethod_Algo = CanonicalizationMethod.EXCLUSIVE, // Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
	digestMethodAlog  =  DigestMethod.SHA256 //"http://www.w3.org/2001/04/xmlenc#sha256" // Constants.ALGO_ID_DIGEST_SHA1, org.apache.ws.security.handler.WSHandlerConstants.SIG_DIGEST_ALGO
	;

	static final String SOAP_PROTOCOL = SOAPConstants.SOAP_1_2_PROTOCOL;
	static String certEncodedID_KeyIdentifier_WsuID = "X509Token", timeStampID = "Timestamp", signedBodyID = "MsgBody";

	static boolean inclusiveNamespaceCanonicalization = true, inclusiveNamespaceTransform = true, useTimeStamp = true;
	/*
	<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" PrefixList="ser soapenv" />
	</ds:CanonicalizationMethod>

	<ds:Transforms>
		<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
			<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="urn v1" />
		</ds:Transform>
	</ds:Transforms>
	 */
	static String
	canonicalizationPrefixListName = "soapenv urn v1",
	transformPrefixListName = "urn v1";

	static String path = "",  // "C:/Yash/Certs/", 
		privateKeyFilePath = path+"Baeldung.p12", publicKeyFilePath = path+"Baeldung.cer", passwordPrivateKey = "password";
	
	static String bodyXML = "<tem:Add xmlns:tem=\"http://tempuri.org/\">\r\n"
			+ " <tem:intA>3</tem:intA>\r\n"
			+ " <tem:intB>4</tem:intB>\r\n"
			+ "</tem:Add>";
	
	static {
		if (Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
			System.out.println("JVM Installing BouncyCastle Security Providers to the Runtime");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} else {
			System.out.println("JVM Installed with BouncyCastle Security Providers");
		}
	}
	public static X509Certificate loadPublicKeyX509(InputStream cerFileStream) throws CertificateException, NoSuchProviderException {
		CertificateFactory  certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(cerFileStream);
		return x509Certificate;
	}
	public static PrivateKey loadPrivateKeyforSigning(InputStream cerFileStream, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12"); //, "BC");
		keyStore.load(cerFileStream, password.toCharArray());
		
		Enumeration<String> keyStoreAliasEnum = keyStore.aliases();
		PrivateKey privateKey = null;
		String alias = null;
		if ( keyStoreAliasEnum.hasMoreElements() ) {
			alias = keyStoreAliasEnum.nextElement();
			if (password != null) {
				privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			}
		}
		return privateKey;
	}

	static X509Certificate loadPublicKeyX509;
	static PrivateKey privateKey;
	
	/** https://www.w3.org/TR/xmldsig-core/#sec-X509Data
	 * https://www.ibm.com/docs/en/was-zos/9.0.5?topic=services-key-information
The key information types in the WS-Security bindings specify different mechanisms for referencing security tokens by using the
<wsse:SecurityTokenReference> element within the <ds:KeyInfo> element.
The following key information types are available in the WS-Security bindings:
	+ Security token reference [BinarySecurityToken - #X.509v3]
	  The X509Certificate element, which contains a base64-encoded [X509V3] certificate
	+ Key identifier           [KeyIdentifier       - #X509SubjectKeyIdentifier]
	  The X509SKI element, which contains the base64 encoded plain (i.e. non-DER-encoded) value of a X509 V.3 SubjectKeyIdentifier extension
	- X509 issuer name and issuer serial
	  The deprecated X509IssuerSerial element, which contains an X.509 issuer distinguished name/serial number pair.
	~ Embedded token
	~ Thumbprint (JAX-WS only)
	~ Key name (JAX-RPC only)
	*/
	
	static void loadCerts() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
		InputStream cerFileStream = getCerFileStream(true, publicKeyFilePath);
		loadPublicKeyX509 = loadPublicKeyX509(cerFileStream);
		PublicKey publicKey = loadPublicKeyX509.getPublicKey();
		System.out.println("loadPublicKey : "+ publicKey);
		
		InputStream pkcs_FileStream = getCerFileStream(true, privateKeyFilePath);
		privateKey = loadPrivateKeyforSigning(pkcs_FileStream, passwordPrivateKey);
	}
	/* An UUID is stated in 32 hexadecimal digits divided into five groups, in mismatch and separated by hyphens: 8-4-4-4-12. An UUID 
	is thus composed of 36 characters: 32 hexadecimal digits and four hyphens.	
	*/
	static UUID getUUID() {
		UUID randomUUID = UUID.randomUUID();
		System.out.println("UUID:"+ randomUUID); // 270200bc-f027-41ef-a8ac-35c7074fd25e
		return randomUUID;
	}
	
	enum WSSecurityBinding {
		BinarySecurityToken, SubjectKeyIdentifier, IssuerName_SerialNumber;
	}
	public static void main(String[] args) throws Exception {
		getUUID();
		loadCerts();
		
		MessageFactory messageFactory = MessageFactory.newInstance(SOAP_PROTOCOL);
		SOAPMessage soapMsgTemp = messageFactory.createMessage();
		
		//soapMsgTemp = getSOAPMessagefromHeaderDataXML(soapMsgTemp);
		SOAPMessage soapMsg = getSOAPMessagefromBodyDataXML(soapMsgTemp, bodyXML);
		System.out.println("SOAP:\n"+ getSoapMessageFromStream( soapMsg ));
		System.out.println("Final SOAP:\n"+ getSoapMessageFromStream( getFinalSoapMessage(soapMsg) ));
		
		WSSecurityBinding keyIdentifier = WSSecurityBinding.BinarySecurityToken;
		
		switch (keyIdentifier) {
		case BinarySecurityToken:
			//BinarySecurityToken: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3
			SOAPMessage ws_Security_signature_BinarySecurityToken = WS_Security_signature_BinarySecurityToken(soapMsg);
			System.out.println("WSS Binary Security Tocken Reference:\n"+getSoapMessage(ws_Security_signature_BinarySecurityToken));
			break;
		case SubjectKeyIdentifier:
			// Certificate Must not be self signed. It must be issued by CA [qualified certificate for electronic seal]
			SOAPMessage ws_Security_signature_KeyIdentifier = WS_Security_signature_KeyIdentifier(soapMsg);
			System.out.println("WSS Key Identifier:\n"+getSoapMessage(ws_Security_signature_KeyIdentifier));
			break;
		case IssuerName_SerialNumber:
			SOAPMessage ws_Security_signature_IssuerSerial = WS_Security_signature_IssuerName_and_SerialNumber(soapMsg);
			System.out.println("WSS X509 issuer name and issuer serial:\n"+getSoapMessage(ws_Security_signature_IssuerSerial));
			break;
		}
		
		
		byte[] authorityInfoAccess = loadPublicKeyX509.getExtensionValue(Extension.authorityInfoAccess.getId());
		byte[] certificatePolicies = loadPublicKeyX509.getExtensionValue(Extension.certificatePolicies.getId());
		if (authorityInfoAccess != null && certificatePolicies != null) {
			System.out.println("authorityInfoAccess : "+ new String(authorityInfoAccess, "UTF-8") );
			System.out.println("certificatePolicies : "+ new String(certificatePolicies, "UTF-8") );
		} else {
			System.out.println("authorityInfoAccess : "+authorityInfoAccess);
			System.out.println("certificatePolicies : "+certificatePolicies);
		}
		//System.out.println("authorityInfoAccess : "+ authorityInfoAccess != null?(new String(authorityInfoAccess)):"Empty" );
		
		getCertInfo(loadPublicKeyX509);
	}
	
	public static TBSCertificateStructure getCertInfo(X509Certificate cert) throws CertificateEncodingException, IOException {
		byte[] encoded = cert.getEncoded();
		ByteArrayInputStream bIn = new ByteArrayInputStream(encoded); // Public Key Encoded.
	    ASN1InputStream aIn = new ASN1InputStream(bIn);
	    ASN1Sequence asn1Sequence = (ASN1Sequence) aIn.readObject();
	    //        String dump = ASN1Dump.dumpAsString(seq);
	    X509CertificateStructure obj = new X509CertificateStructure(asn1Sequence);
	    TBSCertificateStructure tbsCert = obj.getTBSCertificate();
	    
	    System.out.println("X509CertificateStructure Issuer:"+tbsCert.getIssuer());
	    System.out.println(" Subject:"+tbsCert.getSubject().toString());
	    System.out.println(" SerialNumber:"+tbsCert.getSerialNumber());
	    
	    return tbsCert;
	}

	public static SOAPMessage WS_Security_signature_IssuerName_and_SerialNumber(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		SOAPElement X509Data = securityTokenReference.addChildElement("X509Data", MessageConstants.DSIG_PREFIX, MessageConstants.DSIG_NS);
		SOAPElement X509IssuerSerial = X509Data.addChildElement("X509IssuerSerial", MessageConstants.DSIG_PREFIX);
		
		SOAPElement X509IssuerName = X509IssuerSerial.addChildElement("X509IssuerName", MessageConstants.DSIG_PREFIX);
		X509IssuerName.addTextNode( getCertInfo(loadPublicKeyX509).getIssuer().toString() );
		
		SOAPElement X509SerialNumber = X509IssuerSerial.addChildElement("X509SerialNumber", MessageConstants.DSIG_PREFIX);
		X509SerialNumber.addTextNode( getCertInfo(loadPublicKeyX509).getSerialNumber().toString() );
		
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(transformPrefixListName);
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}
			
		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(canonicalizationPrefixListName);
				
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}
	
	// https://security.stackexchange.com/questions/200295/the-difference-between-subject-key-identifier-and-sha1fingerprint-in-x509-certif
	public static String getX509v3SubjectKeyIdentifier_CertEncoded(X509Certificate cert) throws IOException, CertificateEncodingException {
		// https://github.com/mulderbaba/webservices-osgi/blob/7090b58bd4cdf5fab4af14d54cb20bb45c074de2/com/sun/xml/wss/core/reference/X509SubjectKeyIdentifier.java#L108
		String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14", Authority_KEY_IDENTIFIER_OID = "2.5.29.35";
        byte[] subjectKeyIdentifier = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID); //  org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()
        System.out.println("X509SubjectKeyIdentifier ExtensionValue #"+subjectKeyIdentifier);
        if (subjectKeyIdentifier == null) {
        	getCertInfo(cert);
        	
        	System.err.println("PKIX Certificate: Certificate is Self-Signed (or) CAs MUST mark this extension as non-critical. https://tools.ietf.org/html/rfc5280#page-28");
        	// https://stackoverflow.com/a/31183447/5081877
        	byte[] extensionValue = cert.getExtensionValue(Authority_KEY_IDENTIFIER_OID);
        	System.out.println("Authority Key Identifier ExtensionValue #"+extensionValue);
			//byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
			//AuthorityKeyIdentifier authorityKeyIdentifier23 = AuthorityKeyIdentifier.getInstance(octets);
			//byte[] keyIdentifier = authorityKeyIdentifier23.getKeyIdentifier();
        	
        	throw new NullPointerException("SubjectKeyIdentifier OBJECT IDENTIFIER Value is Empty.");
        }
        sun.security.util.DerValue derVal = new sun.security.util.DerValue(
                new sun.security.util.DerInputStream(subjectKeyIdentifier).getOctetString());
        sun.security.x509.KeyIdentifier keyId = new sun.security.x509.KeyIdentifier(derVal.getOctetString());
        byte[] keyIDF = keyId.getIdentifier();
        String encodeToString = Base64.getEncoder().encodeToString(keyIDF);
        System.out.println("Subject Key Identifier Encoded Val: "+encodeToString );
        return encodeToString;
	}
	public static SOAPMessage WS_Security_signature_KeyIdentifier(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX);
		
		SOAPElement reference = securityTokenReference.addChildElement("KeyIdentifier", MessageConstants.WSSE_PREFIX);
		reference.setAttributeNS(null, "EncodingType", MessageConstants.BASE64_ENCODING_NS);
		reference.setAttributeNS(null, "ValueType", MessageConstants.X509SubjectKeyIdentifier_NS);
		reference.addTextNode( getX509v3SubjectKeyIdentifier_CertEncoded(loadPublicKeyX509) );
		
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(transformPrefixListName);
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}

		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(canonicalizationPrefixListName);
				
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}
	
	
	
	public static String getBinarySecurityToken_CertEncoded(X509Certificate cert) throws CertificateEncodingException {
		byte[] certByte = cert.getEncoded();
		String encodeToString = Base64.getEncoder().encodeToString(certByte);
		return encodeToString;
	}
	public static SOAPMessage WS_Security_signature_BinarySecurityToken(SOAPMessage soapMsg) throws Exception {
		
		// A new SOAPMessage object contains: â€¢SOAPPart object â€¢SOAPEnvelope object â€¢SOAPBody object â€¢SOAPHeader object 
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		soapBody.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), signedBodyID);
		
		// Adding NameSpaces to the Envelope
		soapEnv.addNamespaceDeclaration(MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		soapEnv.addNamespaceDeclaration(MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS);
		soapEnv.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
		soapEnv.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		// <wsse:Security> element adding to Header Part
		SOAPElement securityElement = soapHeader.addChildElement("Security", MessageConstants.WSSE_PREFIX, MessageConstants.WSSE_NS);
		//securityElement.addNamespaceDeclaration("wsu", WSU_NS);
		
		/** SecurityTokenReference (Start) */
		// Add Binary Security Token. - <wsse:BinarySecurityToken EncodingType="...#Base64Binary" ValueType="...#X509v3" wsu:Id="X509Token">The base64 encoded value of the ROS digital certificate.</wsse:BinarySecurityToken>
		SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", MessageConstants.WSSE_PREFIX);
		binarySecurityToken.setAttribute("ValueType", MessageConstants.X509v3_NS);
		binarySecurityToken.setAttribute("EncodingType", MessageConstants.BASE64_ENCODING_NS);
		binarySecurityToken.setAttribute("wsu:Id", certEncodedID_KeyIdentifier_WsuID);
		binarySecurityToken.addTextNode( getBinarySecurityToken_CertEncoded(loadPublicKeyX509) );
		
		// Add signature element - <wsse:Security> <ds:Signature> <ds:KeyInfo> <wsse:SecurityTokenReference>
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference", MessageConstants.WSSE_PREFIX);
		SOAPElement reference = securityTokenReference.addChildElement("Reference", MessageConstants.WSSE_PREFIX);
		reference.setAttribute("URI", "#"+certEncodedID_KeyIdentifier_WsuID); // <wsse:BinarySecurityToken wsu:Id="X509Token"
		/** SecurityTokenReference (End) */
		
		// <ds:SignedInfo>
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		//Digest method - <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(digestMethodAlog, null);
		
		ArrayList<Transform> transformList = new ArrayList<Transform>();
		//Transform - <ds:Reference URI="#Body">
		Transform envTransform = null;
		if (inclusiveNamespaceTransform) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(transformPrefixListName);
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, excC14NParameterSpec);
			transformList.add(envTransform);
		} else {
			envTransform = xmlSignatureFactory.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
			transformList.add(envTransform);
		}
			//References <ds:Reference URI="#Body">
			ArrayList<Reference> refList = new ArrayList<Reference>();
				Reference refBody = xmlSignatureFactory.newReference("#"+signedBodyID, digestMethod, transformList, null, null);
			refList.add(refBody);
			if (useTimeStamp) {
				Reference refTS   = xmlSignatureFactory.newReference("#"+timeStampID,  digestMethod, transformList, null, null);
			refList.add(refTS);
			}
			
		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		javax.xml.crypto.dsig.CanonicalizationMethod cm;
		if (inclusiveNamespaceCanonicalization) {
			List<String> prefixList = new ArrayList<String>();
			prefixList.add(canonicalizationPrefixListName);
				
			ExcC14NParameterSpec excC14NParameterSpec = new ExcC14NParameterSpec(prefixList);
			
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, excC14NParameterSpec);
		} else {
			cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethod_Algo, (C14NMethodParameterSpec) null);
		}
		//javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(canonicalizationMethodAlog_INCLUSIVE, (C14NMethodParameterSpec) null);

		javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(signatureMethod_Algo, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix(MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
		signContext.putNamespacePrefix(MessageConstants.WSU_NS, MessageConstants.WSU_PREFIX);

		signContext.setIdAttributeNS(soapBody, MessageConstants.WSU_NS, "Id");
		if (useTimeStamp ) {
			SOAPElement timeStamp = getTimeStamp(soapEnv, securityElement);
			signContext.setIdAttributeNS(timeStamp, MessageConstants.WSU_NS, "Id");
		}
		
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
		javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");

		signature.sign(signContext);
		return soapMsg;
	}

	public static SOAPElement getTimeStamp(SOAPEnvelope soapEnv, SOAPElement securityElement) throws SOAPException {
		SOAPElement timestamp = null;
		int liveTimeInSeconds = 60;
		timestamp = securityElement.addChildElement("Timestamp", MessageConstants.WSU_PREFIX);
		timestamp.addAttribute(soapEnv.createName("Id", MessageConstants.WSU_PREFIX, MessageConstants.WSU_NS), timeStampID);
			String DATE_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
			DateTimeFormatter timeStampFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN);
		timestamp.addChildElement("Created", MessageConstants.WSU_PREFIX).setValue(timeStampFormatter.format(ZonedDateTime.now().toInstant().atZone(ZoneId.of("UTC"))));
		timestamp.addChildElement("Expires", MessageConstants.WSU_PREFIX).setValue(timeStampFormatter.format(ZonedDateTime.now().plusSeconds(liveTimeInSeconds).toInstant().atZone(ZoneId.of("UTC"))));
		return timestamp;
	}

	public static String getSoapMessage(SOAPMessage soapMessage) throws Exception {
		SOAPEnvelope soapEnv = soapMessage.getSOAPPart().getEnvelope();
		Document ownerDocument = soapEnv.getOwnerDocument();
		String stringDocument = toStringDocument(ownerDocument);
		//System.out.println("SoapMessage: "+stringDocument);
		return stringDocument;
	}
	public static String toStringDocument(Document doc) throws TransformerException {
		StringWriter sw = new StringWriter();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

		transformer.transform(new DOMSource(doc), new StreamResult(sw));
		return sw.toString();
	}
	
	public static SOAPMessage getSOAPMessagefromHeaderDataXML(SOAPMessage soapMsg) throws Exception {
		SOAPEnvelope soapEnv = soapMsg.getSOAPPart().getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader();
		if (soapHeader == null) {
			soapHeader = soapEnv.addHeader();
			System.out.println("Provided SOAP XML does not contains any Header part. So creating it.");
		}
		
		String SCHEMA = "http://tempuri.org/", SCHEMA_PREFIX = "tem";
		
		soapHeader.addNamespaceDeclaration(SCHEMA_PREFIX, SCHEMA);
		QName qName = new QName(SCHEMA, "Add", SCHEMA_PREFIX);
		SOAPHeaderElement Add_Ele = soapHeader.addHeaderElement(qName);
		SOAPElement intA_Ele = Add_Ele.addChildElement("intA", SCHEMA_PREFIX);
		SOAPElement intB_Ele = Add_Ele.addChildElement("intB", SCHEMA_PREFIX);
		intA_Ele.setTextContent("3");
		intB_Ele.setTextContent("4");
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static SOAPMessage getSOAPMessagefromBodyDataXML(SOAPMessage soapMsg, String saopBodyXML) throws Exception {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setIgnoringComments(true);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		InputSource ips = new org.xml.sax.InputSource(new StringReader(saopBodyXML));
		Document docBody = dBuilder.parse(ips);
		System.out.println("Body Data Document: "+docBody.getDocumentElement());
		
		SOAPBody soapBody = soapMsg.getSOAPPart().getEnvelope().getBody();
		soapBody.addDocument(docBody);
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static SOAPMessage getFinalSoapMessage(SOAPMessage soapMsg) throws SOAPException {
		SOAPPart soapPart = soapMsg.getSOAPPart();
		SOAPEnvelope soapEnv = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnv.getHeader(); // soapMessage.getSOAPHeader();
		SOAPBody soapBody = soapEnv.getBody(); // soapMessage.getSOAPBody()
		
		if (SOAP_PROTOCOL.equals("SOAP 1.1 Protocol") || SOAP_PROTOCOL.equals("SOAP 1.2 Protocol")) {
			System.out.println("SOAP 1.1 NamespaceURI: http://schemas.xmlsoap.org/soap/envelope/");
			System.out.println("SOAP 1.2 NamespaceURI: http://www.w3.org/2003/05/soap-envelope/");
			soapEnv.setPrefix("soapenv");
			soapEnv.removeNamespaceDeclaration("SOAP-ENV");
			soapHeader.setPrefix("soapenv");
			soapHeader.removeNamespaceDeclaration("SOAP-ENV");
			soapBody.setPrefix("soapenv");
			soapBody.removeNamespaceDeclaration("SOAP-ENV");
		}
		
		soapMsg.saveChanges();
		return soapMsg;
	}
	
	public static String getSoapMessageFromStream(SOAPMessage soapMessage) throws Exception {
		java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
		soapMessage.writeTo(outputStream);
		String codepage = "UTF-8";
		String stringDocument = new String( outputStream.toByteArray(), codepage );
		//System.out.println("SoapMessage form Stram: "+stringDocument);
		return stringDocument;
	}

	public static InputStream getCerFileStream(boolean isClassPath, String fileName) throws FileNotFoundException {
		InputStream stream = null;
		if (isClassPath) {
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(fileName);
		} else {
			stream = new FileInputStream(fileName);
		}
		return stream;
	}
}