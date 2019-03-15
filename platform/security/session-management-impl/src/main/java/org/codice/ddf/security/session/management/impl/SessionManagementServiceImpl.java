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

import ddf.security.SecurityConstants;
import ddf.security.Subject;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import ddf.security.assertion.saml.impl.SecurityAssertionSaml;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.service.SecurityManager;
import ddf.security.service.SecurityServiceException;
import java.net.URI;
import java.time.Clock;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.codice.ddf.configuration.SystemBaseUrl;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.codice.ddf.security.session.management.service.SessionManagementService;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SessionManagementServiceImpl implements SessionManagementService {

  private static final Logger LOGGER = LoggerFactory.getLogger(SessionManagementServiceImpl.class);

  private SecurityManager securityManager;

  private Clock clock = Clock.systemUTC();

  @Override
  public String getExpiry(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    long timeLeft = 0;
    if (session != null) {
      Object securityToken = session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
      if (securityToken instanceof SecurityTokenHolder) {
        timeLeft = getTimeLeft((SecurityTokenHolder) securityToken);
      }
    }
    return Long.toString(timeLeft);
  }

  @Override
  public String getRenewal(HttpServletRequest request) {
    HttpSession session = request.getSession(false);

    String timeLeft = null;
    if (session != null) {
      Object securityToken = session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
      if (securityToken instanceof SecurityTokenHolder) {
        SecurityTokenHolder tokenHolder = (SecurityTokenHolder) securityToken;
        Object token = tokenHolder.getSecurityToken();

        try {
          doRenew(token, tokenHolder);
        } catch (SecurityServiceException e) {
          LOGGER.error("Failed to renew", e);
          return null;
        }

        timeLeft = Long.toString(getTimeLeft(tokenHolder));
      }
    }
    return timeLeft;
  }

  @Override
  public URI getInvalidate(HttpServletRequest request) {
    String requestQueryString = request.getQueryString();
    return URI.create(
        SystemBaseUrl.EXTERNAL
            .constructUrl("/logout?noPrompt=true")
            .concat(requestQueryString != null ? "&" + requestQueryString : ""));
  }

  private long getTimeLeft(SecurityTokenHolder securityToken) {
    Object token = securityToken.getSecurityToken();

    if (token instanceof SecurityToken) {
      SecurityAssertionSaml securityAssertion = new SecurityAssertionSaml((SecurityToken) token);
      long time = securityAssertion.getNotOnOrAfter().getTime();
      return Math.max(time - clock.millis(), 0);

    } else if (token instanceof OidcCredentials) {
      OidcCredentials oidcCredentials = (OidcCredentials) token;
      SecurityAssertionJwt securityAssertion =
          new SecurityAssertionJwt(oidcCredentials.getIdToken());
      long time = securityAssertion.getNotOnOrAfter().getTime();
      return Math.max(time - clock.millis(), 0);
    }
    return 0L;
  }

  private void doRenew(Object securityToken, SecurityTokenHolder tokenHolder)
      throws SecurityServiceException {
    if (securityToken instanceof SecurityToken) {
      SAMLAuthenticationToken samlToken =
          new SAMLAuthenticationToken(
              ((SecurityToken) securityToken).getPrincipal(), (SecurityToken) securityToken);
      Subject subject = securityManager.getSubject(samlToken);
      for (Object principal : subject.getPrincipals().asList()) {
        if (principal instanceof SecurityAssertion) {
          tokenHolder.setSecurityToken(((SecurityAssertion) principal).getToken());
        }
      }
    }
  }

  public void setSecurityManager(SecurityManager securityManager) {
    this.securityManager = securityManager;
  }

  public void setClock(Clock clock) {
    this.clock = clock;
  }
}
