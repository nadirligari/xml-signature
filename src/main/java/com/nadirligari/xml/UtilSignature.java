package com.nadirligari.xml;


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import lombok.extern.slf4j.Slf4j;

/**
 * 
 * @author Nadir Ligari
 *
 */
@Slf4j
public class UtilSignature {


	// ================================================================================
	// SIGN DOCUMENT
	// ================================================================================
	// UtilKeys.signDocument (document, privateKey, "element", "data",
	// DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
	public static String signDocument(String xml, // RETURN VALUE
			Key privateKey, // Private Key used to sign XML Element
//			String referenceURI, // "#data"
			String digestMethod, // DigestMethod.SHA1
			String signatureMethod, // SignatureMethod.RSA_SHA1
			Key publicKey) throws Exception {
		Document document = UtilXML.stringToDocument(xml);
		Element rootElement = getRoot(document);
		// CREATE SIGNATURE FACTORY
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		// GET REFERENCE
		Reference reference = factory.newReference("", factory.newDigestMethod(digestMethod, null),
				Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
				null, null);

		// SPECIFY SIGNATURE TYPE
		SignedInfo signedInfo = factory.newSignedInfo(
				factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
				factory.newSignatureMethod(signatureMethod, null), Collections.singletonList(reference));

		// PREPARE SIGN CONTEXT
		DOMSignContext domSignContext = new DOMSignContext(privateKey, rootElement);

		// Pass the Public Key File Path
		KeyInfo keyInfo = getKeyInfo(factory, (PublicKey) publicKey);

		// SIGN DOCUMENT
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
		signature.sign(domSignContext);
		return UtilXML.documentToString(document);
	}
	
	public static String signDocument(String xml, // RETURN VALUE
			Key privateKey, // Private Key used to sign XML Element
//			String referenceURI, // "#data"
			String digestMethod, // DigestMethod.SHA1
			String signatureMethod, // SignatureMethod.RSA_SHA1
			X509Certificate cert) throws Exception {
		Document document = UtilXML.stringToDocument(xml);
		Element rootElement = getRoot(document);
		// CREATE SIGNATURE FACTORY
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		// GET REFERENCE
		Reference reference = factory.newReference("", factory.newDigestMethod(digestMethod, null),
				Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
				null, null);

		// SPECIFY SIGNATURE TYPE
		SignedInfo signedInfo = factory.newSignedInfo(
				factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
				factory.newSignatureMethod(signatureMethod, null), Collections.singletonList(reference));

		// PREPARE SIGN CONTEXT
		DOMSignContext domSignContext = new DOMSignContext(privateKey, rootElement);

//		// FIX IF referenceURI POINTS TO Id ATTRIBUTE
//		if (!referenceURI.equals("")) {
//			domSignContext.setIdAttributeNS(rootElement, null, "Id");
//		}

		// Pass the Public Key File Path
		KeyInfo keyInfo = getKeyInfo(factory, cert);

		// SIGN DOCUMENT
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
		signature.sign(domSignContext);
		return UtilXML.documentToString(document);
	}
	
	private static Element getRoot(Document document) {
		return document.getDocumentElement();
	}
	
	public static boolean validateAndVerifyXmlSignature(String xml, PublicKey publicKey) throws Exception {
		boolean validFlag = false;
		Document doc = UtilXML.stringToDocument(xml);
		NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("No XML Digital Signature Found, document is discarded");
		}
		DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		validFlag = signature.validate(valContext);
		return validFlag;
	}



	private static Key loadPublicKey(KeyFactory keyFactory, byte[] keyBytes) throws InvalidKeySpecException {
		// decode public key
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
		return keyFactory.generatePublic(pubSpec);
	}


	private static KeyInfo getKeyInfo(XMLSignatureFactory xmlSigFactory, PublicKey pubKey) throws KeyException {
		KeyInfo keyInfo = null;
		KeyValue keyValue = null;
		KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();
		keyValue = keyInfoFact.newKeyValue(pubKey);
		keyInfo = keyInfoFact.newKeyInfo(Collections.singletonList(keyValue));
		return keyInfo;
	}
	
	private static KeyInfo getKeyInfo(XMLSignatureFactory xmlSigFactory, X509Certificate cert) throws KeyException {
		KeyInfo keyInfo = null;
		KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();
		
		List xDataList = new ArrayList<>();
		xDataList.add(cert.getSubjectX500Principal().getName());
		xDataList.add(cert);
		
		X509Data xData = keyInfoFact.newX509Data(xDataList);
		keyInfo = keyInfoFact.newKeyInfo(Collections.singletonList(xData));
		return keyInfo;
	}
	
	public static PublicKey loadPublicKeyFromCert(byte[] cert) throws CertificateException, IOException {
		X509Certificate certificate = loadCertificate(cert);
		return certificate.getPublicKey();
	}

	public static X509Certificate loadCertificate(byte[] cert) throws CertificateException, IOException {
		try (InputStream fin = new ByteArrayInputStream(cert);) {
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			return certificate;
		}
	}
	
	
	public static PublicKey loadPGPPublicKey(byte[] pubKey) throws Exception {
		try (InputStream in = new ByteArrayInputStream(pubKey)) {
			PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in),
					new JcaKeyFingerprintCalculator());
			Iterator<PGPPublicKeyRing> rIt = pubRings.getKeyRings();
			while (rIt.hasNext()) {
				PGPPublicKeyRing pgpPub = rIt.next();
				Iterator<PGPPublicKey> it = pgpPub.getPublicKeys();
				while (it.hasNext()) {
					PGPPublicKey pgpKey = it.next();
					log.debug(pgpKey.getClass().getName() + " KeyID: " + Long.toHexString(pgpKey.getKeyID()) + " type: "
							+ pgpKey.getAlgorithm() + " fingerprint: "
							+ new String(Hex.encode(pgpKey.getFingerprint())));
					{
						PublicKey jceKey = new JcaPGPKeyConverter().getPublicKey(pgpKey);
						return jceKey;
					}
				}
			}
		}
		return null;
	}
	
	public static PrivateKey loadPGPPrivateKey(byte[] privateKey, String passphrase) throws Exception {
        InputStream pgpIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKey));

        PGPObjectFactory pgpFact = new PGPObjectFactory(pgpIn, new JcaKeyFingerprintCalculator());
        PGPSecretKeyRing pgpSecRing = (PGPSecretKeyRing) pgpFact.nextObject();
        PGPSecretKey pgpSec = pgpSecRing.getSecretKey();
        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
				new BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray());
        PGPPrivateKey pgpPriv = pgpSec.extractPrivateKey(decryptorFactory);

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
        // this is the part i was missing from Peter Dettman's answer. pass BC provider to the converter
        converter.setProvider(new BouncyCastleProvider());
        PrivateKey key = converter.getPrivateKey(pgpPriv);
        return key;
    }
}