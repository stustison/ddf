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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.text.ParseException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.context.WebContext;
import org.pac4j.oidc.credentials.OidcCredentials;

public class OidcRealmTest {

  private OidcRealm realm;

  private OidcAuthenticationToken authenticationToken;

  private OidcCredentials oidcCredentials;

  @Before
  public void setup() throws ParseException {
    realm = new OidcRealm();
    authenticationToken = mock(OidcAuthenticationToken.class);
    oidcCredentials = mock(OidcCredentials.class);
    when(authenticationToken.getCredentials()).thenReturn(oidcCredentials);
    WebContext webContext = mock(WebContext.class);
    when(authenticationToken.getContext()).thenReturn(webContext);
    JWT jwt = mock(JWT.class);
    when(oidcCredentials.getIdToken()).thenReturn(jwt);
    AccessToken accessToken = mock(AccessToken.class);
    AuthorizationCode authorizationCode = new AuthorizationCode();
    when(oidcCredentials.getIdToken()).thenReturn(jwt);
    when(oidcCredentials.getAccessToken()).thenReturn(accessToken);
    when(oidcCredentials.getCode()).thenReturn(authorizationCode);
  }

  @Test
  public void testSupports() {
    boolean supports = realm.supports(authenticationToken);
    assertTrue(supports);
  }

  @Test
  public void testSupportsFails() {

    // null token
    boolean supports = realm.supports(null);
    assertFalse(supports);

    // null credentials
    when(authenticationToken.getCredentials()).thenReturn(null);
    supports = realm.supports(authenticationToken);
    assertFalse(supports);

    // token not an OidcAuthenticationToken type
    SAMLAuthenticationToken samlAuthenticationToken = mock(SAMLAuthenticationToken.class);
    when(samlAuthenticationToken.getCredentials()).thenReturn("creds");
    supports = realm.supports(samlAuthenticationToken);
    assertFalse(supports);
  }

  @Test
  public void testDoGetAuthenticationInfo() throws ParseException {
    JWT jwt = getValidJwt();
    when(oidcCredentials.getIdToken()).thenReturn(jwt);

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(authenticationToken);
    assertNotNull(authenticationInfo.getCredentials());
    assertNotNull(authenticationInfo.getPrincipals());
    assertEquals("admin", authenticationInfo.getPrincipals().getPrimaryPrincipal());
  }

  @Test
  public void testDoGetAuthenticationInfoWithMissingInfo() throws ParseException {
    JWT jwt = getIncompleteJwt();
    when(oidcCredentials.getIdToken()).thenReturn(jwt);

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(authenticationToken);
    assertNotNull(authenticationInfo.getCredentials());
    assertNotNull(authenticationInfo.getPrincipals());
    assertNotNull(authenticationInfo.getPrincipals().getPrimaryPrincipal());
    assertNotEquals("admin", authenticationInfo.getPrincipals().getPrimaryPrincipal());
  }

  @Test
  public void testDoGetAuthenticationInvalid() {
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
