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
package org.codice.ddf.security.oidc.realm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import java.text.ParseException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.junit.Test;
import org.pac4j.oidc.credentials.OidcCredentials;

public class OidcRealmTest {

  @Test
  public void testSupports() {
    OidcRealm realm = new OidcRealm();
    AuthenticationToken authenticationToken = mock(OidcAuthenticationToken.class);
    when(authenticationToken.getCredentials()).thenReturn("creds");
    boolean supports = realm.supports(authenticationToken);
    assertTrue(supports);
  }

  @Test
  public void testSupportsFails() {
    OidcRealm realm = new OidcRealm();
    AuthenticationToken authenticationToken = mock(OidcAuthenticationToken.class);

    // null token
    boolean supports = realm.supports(null);
    assertFalse(supports);

    // null credentials
    when(authenticationToken.getCredentials()).thenReturn(null);
    supports = realm.supports(authenticationToken);
    assertFalse(supports);

    // token not an OidcAuthenticationToken type
    authenticationToken = mock(SAMLAuthenticationToken.class);
    when(authenticationToken.getCredentials()).thenReturn("creds");
    supports = realm.supports(authenticationToken);
    assertFalse(supports);
  }

  @Test
  public void testDoGetAuthenticationInfo() throws ParseException {
    OidcRealm realm = new OidcRealm();

    OidcCredentials credentials = new OidcCredentials();
    JWT jwt = getValidJwt();
    credentials.setIdToken(jwt);

    AuthenticationToken authenticationToken = mock(OidcAuthenticationToken.class);
    SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
    SecurityAssertion securityAssertion = mock(SecurityAssertion.class);
    when(securityAssertion.getToken()).thenReturn(credentials);
    when(securityAssertion.getTokenType()).thenReturn(SecurityAssertionJwt.JWT_TOKEN_TYPE);
    principalCollection.add(securityAssertion, "default");
    when(authenticationToken.getCredentials()).thenReturn(principalCollection);

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(authenticationToken);
    assertNotNull(authenticationInfo.getCredentials());
    assertNotNull(authenticationInfo.getPrincipals());
    assertEquals("admin", authenticationInfo.getPrincipals().getPrimaryPrincipal());
  }

  @Test
  public void testDoGetAuthenticationInfoWithMissingInfo() throws ParseException {
    OidcRealm realm = new OidcRealm();

    OidcCredentials credentials = new OidcCredentials();
    JWT jwt = getIncompleteJwt();
    credentials.setIdToken(jwt);

    AuthenticationToken authenticationToken = mock(OidcAuthenticationToken.class);
    SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
    SecurityAssertion securityAssertion = mock(SecurityAssertion.class);
    when(securityAssertion.getToken()).thenReturn(credentials);
    when(securityAssertion.getTokenType()).thenReturn(SecurityAssertionJwt.JWT_TOKEN_TYPE);
    principalCollection.add(securityAssertion, "default");

    when(authenticationToken.getCredentials()).thenReturn(principalCollection);

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(authenticationToken);
    assertNotNull(authenticationInfo.getCredentials());
    assertNotNull(authenticationInfo.getPrincipals());
    assertNotNull(authenticationInfo.getPrincipals().getPrimaryPrincipal());
    assertNotEquals("admin", authenticationInfo.getPrincipals().getPrimaryPrincipal());
  }

  @Test
  public void testDoGetAuthenticationInvalid() {
    OidcRealm realm = new OidcRealm();

    OidcCredentials credentials = new OidcCredentials();
    JWT jwt = mock(JWT.class);
    credentials.setIdToken(jwt);

    SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
    SecurityAssertion securityAssertion = mock(SecurityAssertion.class);
    when(securityAssertion.getToken()).thenReturn(credentials);
    when(securityAssertion.getTokenType()).thenReturn(SecurityAssertionJwt.JWT_TOKEN_TYPE);
    principalCollection.add(securityAssertion, "default");

    AuthenticationToken authenticationToken = mock(OidcAuthenticationToken.class);
    when(authenticationToken.getCredentials()).thenReturn(principalCollection);

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(authenticationToken);
    assertNotNull(authenticationInfo.getCredentials());
    assertNotNull(authenticationInfo.getPrincipals());
    assertNull(authenticationInfo.getPrincipals().getPrimaryPrincipal());
  }

  private JWT getValidJwt() throws ParseException {
    String token =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrVXJTaUNpZlpuNDJWNU5ORWtEYlg5bGx5Zk"
            + "9vWkhQLXpGTzA3QktjaGZVIn0.eyJqdGkiOiI1ZTllY2EyNC02ZTg4LTQyY2EtYjFhMC1hYmI4OWU3YmY4"
            + "ODciLCJleHAiOjE1NTg0NzQyNzIsIm5iZiI6MCwiaWF0IjoxNTU4NDczMzcyLCJpc3MiOiJodHRwOi8vbG"
            + "9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiZGRmLmNsaWVudCIsInN1YiI6ImZh"
            + "MGU3NmM1LTVhNTgtNDgzYS1iYjhjLThhM2NmNzJjZGRlNSIsInR5cCI6IklEIiwiYXpwIjoiZGRmLmNsaW"
            + "VudCIsIm5vbmNlIjoiMDhCb1AxRGdSSG1CZE1FdmZIcVdCYWl1T1VtalRDa0kwazJrdXlZNDZHdyIsImF1"
            + "dGhfdGltZSI6MTU1ODQ3MzM3Miwic2Vzc2lvbl9zdGF0ZSI6ImU1YzYyM2FmLTczMmEtNGJkYy1iZWFiLT"
            + "gzMDM3ZjY4MjI3ZCIsImFjciI6IjEiLCJzX2hhc2giOiJ5b0VuS0pjZzZaaDY0ZnFEV2pWMjRBIiwiaHR0"
            + "cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvcm9sZSI6WyJjcm"
            + "VhdGUtcmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXSwiZW1h"
            + "aWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.KwBXF9J6EZ35f76lM"
            + "fwRNSZhtIzoym7ceO4KFe6wKMWb4vf0iPmpwWr1ZcFxHPD7dEfBeI6hKAJL3VtCAvfGVPTB5syvNiMsS7y"
            + "lmfUF88LEnFy8VjkDaL4EaTecyNfsdUTmU68yDFwwcwnls6Qeph5n-dTFCGBvkQduChGr9LmzV_TeFv4Ex"
            + "uta4MN5GTrFkAtV1dhE6odl70hkIVh6j2_1AboSzcDbd7jPDH0AmFTsACYzR6KX0xItsNl-94TrwuPWFmG"
            + "8fLNlrspBoQiL1rycoiu304CDTNV1BcoNb558sGPgxuqVLfhpEmdK-vA-22FjUl5RvVP2A247-yNDyw";
    return SignedJWT.parse(token);
  }

  private JWT getIncompleteJwt() throws ParseException {
    // JWT is valid with a valid payload but doesn't have a subject (sub), and email, or a
    // preferred_username
    String token =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrVXJTaUNpZlpuNDJWNU5ORWtEYlg5bGx5Zk9"
            + "vWkhQLXpGTzA3QktjaGZVIn0.eyJqdGkiOiI1ZTllY2EyNC02ZTg4LTQyY2EtYjFhMC1hYmI4OWU3YmY4OD"
            + "ciLCJleHAiOjE1NTg0NzQyNzIsIm5iZiI6MCwiaWF0IjoxNTU4NDczMzcyLCJpc3MiOiJodHRwOi8vbG9jYW"
            + "xob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiZGRmLmNsaWVudCIsInR5cCI6IklEIiwiYX"
            + "pwIjoiZGRmLmNsaWVudCIsIm5vbmNlIjoiMDhCb1AxRGdSSG1CZE1FdmZIcVdCYWl1T1VtalRDa0kwazJrdX"
            + "lZNDZHdyIsImF1dGhfdGltZSI6MTU1ODQ3MzM3Miwic2Vzc2lvbl9zdGF0ZSI6ImU1YzYyM2FmLTczMmEtNG"
            + "JkYy1iZWFiLTgzMDM3ZjY4MjI3ZCIsImFjciI6IjEiLCJzX2hhc2giOiJ5b0VuS0pjZzZaaDY0ZnFEV2pWMj"
            + "RBIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvcm9sZS"
            + "I6WyJjcmVhdGUtcmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXS"
            + "wiZW1haWxfdmVyaWZpZWQiOmZhbHNlfQ==.KwBXF9J6EZ35f76lMfwRNSZhtIzoym7ceO4KFe6wKMWb4vf0i"
            + "PmpwWr1ZcFxHPD7dEfBeI6hKAJL3VtCAvfGVPTB5syvNiMsS7ylmfUF88LEnFy8VjkDaL4EaTecyNfsdUTmU"
            + "68yDFwwcwnls6Qeph5n-dTFCGBvkQduChGr9LmzV_TeFv4Exuta4MN5GTrFkAtV1dhE6odl70hkIVh6j2_1A"
            + "boSzcDbd7jPDH0AmFTsACYzR6KX0xItsNl-94TrwuPWFmG8fLNlrspBoQiL1rycoiu304CDTNV1BcoNb558s"
            + "GPgxuqVLfhpEmdK-vA-22FjUl5RvVP2A247-yNDyw";
    return SignedJWT.parse(token);
  }
}
