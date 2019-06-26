/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.security.session.management.impl;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ddf.security.SecurityConstants;
import ddf.security.Subject;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.saml.impl.SecurityAssertionSaml;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.http.SessionFactory;
import ddf.security.service.SecurityManager;
import ddf.security.service.SecurityServiceException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@Ignore
public class SessionManagementServiceImplTest {
  private HttpServletRequest request;

  private HttpServletResponse response;

  private SecurityTokenHolder tokenHolder;

  private SecurityToken securityToken;

  private SecurityManager manager;

  private SessionManagementServiceImpl sessionManagementServiceImpl;

  private PrincipalCollection principalCollection;

  private SessionFactory sessionFactory;

  @Before
  public void setup()
      throws ParserConfigurationException, SAXException, IOException, SecurityServiceException {
    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    tokenHolder = mock(SecurityTokenHolder.class);
    securityToken = mock(SecurityToken.class);
    SecurityAssertion principal = mock(SecurityAssertion.class);
    principalCollection = mock(PrincipalCollection.class);
    Subject subject = mock(Subject.class);
    manager = mock(SecurityManager.class);

    when(principal.getToken()).thenReturn(securityToken);
    when(principalCollection.asList()).thenReturn(Collections.singletonList(principal));
    when(subject.getPrincipals()).thenReturn(principalCollection);
    when(manager.getSubject(isA(SAMLAuthenticationToken.class))).thenReturn(subject);
    when(securityToken.getToken())
        .thenReturn(
            readXml(getClass().getClassLoader().getResourceAsStream("saml.xml"))
                .getDocumentElement());
    when(tokenHolder.getPrincipals()).thenReturn(principalCollection);
    when(request.getSession(false)).thenReturn(session);
    when(session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(tokenHolder);
    sessionManagementServiceImpl = new SessionManagementServiceImpl();
    sessionManagementServiceImpl.setSecurityManager(manager);

    Collection<SecurityAssertion> assertionList = new ArrayList<>();
    when(principalCollection.byType(SecurityAssertion.class)).thenReturn(assertionList);
    SecurityAssertion securityAssertion = new SecurityAssertionSaml(securityToken);
    assertionList.add(securityAssertion);
    when(principalCollection.byType(SecurityAssertion.class)).thenReturn(assertionList);

    sessionFactory = mock(SessionFactory.class);
    when(sessionFactory.getOrCreateSession(any())).thenReturn(session);
    sessionManagementServiceImpl.setSessionFactory(sessionFactory);
  }

  @Test
  public void testGetExpiry() {
    sessionManagementServiceImpl.setClock(Clock.fixed(Instant.EPOCH, ZoneId.of("UTC")));
    String expiryString = sessionManagementServiceImpl.getExpiry(request, response);
    assertThat(expiryString, is("4522435794788"));
  }

  @Test
  public void testGetExpirySoonest()
      throws IOException, ParserConfigurationException, SAXException {
    sessionManagementServiceImpl.setClock(Clock.fixed(Instant.EPOCH, ZoneId.of("UTC")));
    SecurityToken soonerToken = mock(SecurityToken.class);
    String saml =
        IOUtils.toString(
            new InputStreamReader(getClass().getClassLoader().getResourceAsStream("saml.xml")));
    saml = saml.replace("2113", "2103");
    when(soonerToken.getToken())
        .thenReturn(readXml(IOUtils.toInputStream(saml, "UTF-8")).getDocumentElement());
    SecurityToken laterToken = mock(SecurityToken.class);
    saml =
        IOUtils.toString(
            new InputStreamReader(getClass().getClassLoader().getResourceAsStream("saml.xml")));
    saml = saml.replace("2113", "2213");
    when(laterToken.getToken())
        .thenReturn(readXml(IOUtils.toInputStream(saml, "UTF-8")).getDocumentElement());
    Collection<SecurityAssertion> assertionList = new ArrayList<>();
    when(principalCollection.byType(SecurityAssertion.class)).thenReturn(assertionList);
    SecurityAssertion securityAssertion = new SecurityAssertionSaml(soonerToken);
    assertionList.add(securityAssertion);

    String expiryString = sessionManagementServiceImpl.getExpiry(request, response);

    assertThat(expiryString, is("4206816594788"));
  }

  @Test
  public void testGetRenewal() {
    String renewalString = sessionManagementServiceImpl.getRenewal(request, response);
    assertNotNull(renewalString);
    verify(tokenHolder).setPrincipals(principalCollection);
  }

  @Test
  public void testGetRenewalFails() throws SecurityServiceException {
    when(manager.getSubject(isA(SAMLAuthenticationToken.class)))
        .thenThrow(new SecurityServiceException());
    String renewalString = sessionManagementServiceImpl.getRenewal(request, response);
    assertNull(renewalString);
  }

  @Test
  public void testGetInvalidateNoQueryString() {
    when(request.getRequestURL())
        .thenReturn(
            new StringBuffer("https://localhost:8993/services/internal/session/invalidate"));
    when(request.getQueryString()).thenReturn(null);
    URI invalidateUri = sessionManagementServiceImpl.getInvalidate(request, response);
    assertThat(
        invalidateUri, is(equalTo(URI.create("https://localhost:8993/logout?noPrompt=true"))));
  }

  @Test
  public void testGetInvalidateWithQueryString() {
    when(request.getRequestURL())
        .thenReturn(
            new StringBuffer(
                "https://localhost:8993/services/internal/session/invalidate?prevurl=/admin/"));
    when(request.getQueryString()).thenReturn("prevurl=/admin/");
    URI invalidateUri = sessionManagementServiceImpl.getInvalidate(request, response);
    assertThat(
        invalidateUri,
        is(equalTo(URI.create("https://localhost:8993/logout?noPrompt=true&prevurl=/admin/"))));
  }

  private static Document readXml(InputStream is)
      throws SAXException, IOException, ParserConfigurationException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    dbf.setValidating(false);
    dbf.setIgnoringComments(false);
    dbf.setIgnoringElementContentWhitespace(true);
    dbf.setNamespaceAware(true);

    DocumentBuilder db = dbf.newDocumentBuilder();
    db.setEntityResolver(new DOMUtils.NullResolver());

    return db.parse(is);
  }
}
