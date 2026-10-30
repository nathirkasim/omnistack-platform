package org.tigergate.benchmark;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class LdapAndXpathInjection {

    public static void searchLdapUser(DirContext ctx, String username) throws Exception {
        // VULNERABLE: Concatenating untrusted string into LDAP filter query (CWE-90)
        String filter = "(&(uid=" + username + ")(objectClass=person))";
        ctx.search("ou=users,dc=corp,dc=internal", filter, new SearchControls());
    }

    public static String evaluateXpathUser(Document doc, String username) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        // VULNERABLE: Concatenating untrusted string into XPath expression (CWE-643)
        String expression = "/users/user[@name='" + username + "']/role";
        return xpath.evaluate(expression, doc);
    }
}
