package com.nadirligari.xml;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class UtilXML {

	// =======================================================================================
	// DOCUMENT TO STRING
	// =======================================================================================
	public static String documentToString(Document document) throws Exception {

		DOMSource domSource = new DOMSource(document);

		StringWriter stringWriter = new StringWriter();
		StreamResult streamResult = new StreamResult(stringWriter);

		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		transformer = transformerFactory.newTransformer();
		transformer.transform(domSource, streamResult);

		// RETURN STRING
		return stringWriter.toString();

	}

	// ================================================================================
	// STRING TO DOCUMENT
	// ================================================================================
	public static Document stringToDocument(String xmlString) throws Exception {

		// READ XML STRING
		InputSource inputSource = new InputSource();
		inputSource.setCharacterStream(new StringReader(xmlString));
		// CONVERT TO DOCUMENT
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true); // IMPORTANT
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);

		// RETURN DOCUMENT
		return document;
	}
	
}