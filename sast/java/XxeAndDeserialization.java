package org.tigergate.benchmark;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;

public class XxeAndDeserialization {

    public static Document parseXmlDocument(String xmlContent) throws Exception {
        // VULNERABLE: DocumentBuilderFactory with external entities enabled by default (CWE-611)
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }

    public static Object deserializeUserData(InputStream stream) throws Exception {
        // VULNERABLE: Deserializing untrusted object stream enables remote code execution (CWE-502)
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }
}
