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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.codice.ddf.security.handler.oidc.OidcCallbackEndpoint;
import org.junit.Test;

public class OidcCallbackEndpointTest {

  @Test
  public void testLogout() {
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);

    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession()).thenReturn(session);

    OidcCallbackEndpoint callbackEndpoint = new OidcCallbackEndpoint();
    Response res = callbackEndpoint.logout(request, response);

    verify(request, times(1)).getSession();
    verify(session, times(1)).invalidate();

    assertEquals(HttpStatus.SC_TEMPORARY_REDIRECT, res.getStatus());
    assertEquals(
        "https://localhost:8993/logout", res.getMetadata().get("Location").get(0).toString());
  }
}
