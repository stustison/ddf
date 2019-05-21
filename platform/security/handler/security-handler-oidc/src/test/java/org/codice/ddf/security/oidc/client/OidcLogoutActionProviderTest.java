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
package org.codice.ddf.security.oidc.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableMap;
import ddf.action.Action;
import ddf.security.SecurityConstants;
import ddf.security.common.SecurityTokenHolder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;

public class OidcLogoutActionProviderTest {

  private static final String LOCATION = "https://localhost:8993/services/oidc/logout";

  private OidcLogoutActionProvider oidcLogoutActionProvider;

  @Before
  public void setup() {
    OidcProfileCreator oidcProfileCreator = mock(OidcProfileCreator.class);
    OidcProfile oidcProfile = mock(OidcProfile.class);
    when(oidcProfileCreator.create(any(), any())).thenReturn(oidcProfile);

    OidcLogoutActionBuilder oidcLogoutActionBuilder = mock(OidcLogoutActionBuilder.class);
    RedirectAction redirectAction = mock(RedirectAction.class);
    when(redirectAction.getLocation()).thenReturn(LOCATION);
    when(oidcLogoutActionBuilder.getLogoutAction(any(), any(), any())).thenReturn(redirectAction);

    HandlerConfiguration handlerConfiguration = mock(HandlerConfiguration.class);
    when(handlerConfiguration.getLogoutActionBuilder()).thenReturn(oidcLogoutActionBuilder);
    when(handlerConfiguration.getOidcProfileCreator()).thenReturn(oidcProfileCreator);

    oidcLogoutActionProvider = new OidcLogoutActionProvider(handlerConfiguration);
  }

  @Test
  public void testGetAction() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    SecurityTokenHolder tokenHolder = mock(SecurityTokenHolder.class);
    OidcCredentials credentials = mock(OidcCredentials.class);

    when(tokenHolder.getSecurityToken()).thenReturn(credentials);
    when(session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(tokenHolder);
    when(request.getSession(false)).thenReturn(session);

    Action action =
        oidcLogoutActionProvider.getAction(
            ImmutableMap.of(
                SecurityConstants.SECURITY_SUBJECT,
                credentials,
                "http_request",
                request,
                "http_response",
                response));
    assertEquals(LOCATION, action.getUrl().toString());
  }

  @Test
  public void testGetActionFailure() {
    Object notSubjectMap = new Object();
    Action action = oidcLogoutActionProvider.getAction(notSubjectMap);
    assertNull(action);

    action =
        oidcLogoutActionProvider.getAction(
            ImmutableMap.of(SecurityConstants.SECURITY_SUBJECT, notSubjectMap));
    assertNull(action);
  }

  @Test
  public void testGetActionFailureWrongKey() {
    OidcCredentials credentials = mock(OidcCredentials.class);
    Action action = oidcLogoutActionProvider.getAction(ImmutableMap.of("wrong key", credentials));
    assertNull(action);
  }

  @Test
  public void testGetActionFailsWithoutRequestAndResponse() {
    OidcCredentials credentials = mock(OidcCredentials.class);
    Action action =
        oidcLogoutActionProvider.getAction(
            ImmutableMap.of(SecurityConstants.SECURITY_SUBJECT, credentials));
    assertNull(action);
  }
}
