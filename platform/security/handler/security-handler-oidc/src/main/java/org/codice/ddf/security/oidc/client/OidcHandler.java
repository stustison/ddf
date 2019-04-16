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

import com.google.common.hash.Hashing;
import ddf.security.SecurityConstants;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.common.audit.SecurityLogger;
import ddf.security.http.SessionFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.codice.ddf.platform.filter.AuthenticationException;
import org.codice.ddf.platform.filter.AuthenticationFailureException;
import org.codice.ddf.platform.filter.FilterChain;
import org.codice.ddf.security.handler.api.AuthenticationHandler;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.http.callback.QueryParameterCallbackUrlResolver;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.credentials.authenticator.OidcAuthenticator;
import org.pac4j.oidc.credentials.extractor.OidcExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcHandler implements AuthenticationHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcHandler.class);

  public static final String SOURCE = "OidcHandler";

  public static final String AUTH_TYPE = "OIDC";

  private boolean userAgentCheck = true;

  private HandlerConfiguration handlerConfiguration;

  private SessionFactory sessionFactory;

  public OidcHandler(HandlerConfiguration handlerConfiguration) {
    buildConfiguration(handlerConfiguration);
  }

  public void buildConfiguration(HandlerConfiguration handlerConfiguration) {
    this.handlerConfiguration = handlerConfiguration;
  }

  @Override
  public String getAuthenticationType() {
    return AUTH_TYPE;
  }

  /**
   * Handler implementing OIDC authentication.
   *
   * @param request http request to obtain attributes from and to pass into any local filter chains
   *     required
   * @param response http response to return http responses or redirects
   * @param chain original filter chain (should not be called from your handler)
   * @param resolve flag with true implying that credentials should be obtained, false implying
   *     return if no credentials are found.
   * @return result of handling this request - status and optional tokens
   * @throws AuthenticationFailureException
   */
  @Override
  public HandlerResult getNormalizedToken(
      ServletRequest request, ServletResponse response, FilterChain chain, boolean resolve)
      throws AuthenticationFailureException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    if (httpRequest.getMethod().equals("HEAD")) {
      ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_OK);
      try {
        response.flushBuffer();
      } catch (IOException e) {
        throw new AuthenticationFailureException(
            "Unable to send response to HEAD message from OIDC client.");
      }
      return new HandlerResult(HandlerResult.Status.NO_ACTION, null);
    }

    if (userAgentCheck && userAgentIsNotBrowser(httpRequest)) {
      SecurityLogger.audit("Attempting to log client in as a legacy system.");
      // if we get here, it is most likely an older DDF that is federating
      // it isn't going to understand the redirect to the IdP and it doesn't support ECP
      // so we need to fall back to other handlers to allow it to log in using PKI, Basic or Guest

      return new HandlerResult(HandlerResult.Status.NO_ACTION, null);
    }

    HandlerResult handlerResult = new HandlerResult(HandlerResult.Status.REDIRECTED, null);
    handlerResult.setSource("oidc-" + SOURCE);

    String path = httpRequest.getServletPath();
    LOGGER.debug("Doing OIDC authentication and authorization for path {}", path);

    HttpSession session = httpRequest.getSession(false);
    if (httpRequest.getRequestedSessionId() != null && !httpRequest.isRequestedSessionIdValid()) {
      SecurityLogger.audit(
          "Incoming HTTP Request contained possible unknown session ID [{}] for this server.",
          Hashing.sha256()
              .hashString(httpRequest.getRequestedSessionId(), StandardCharsets.UTF_8)
              .toString());
    }
    if (session == null && httpRequest.getRequestedSessionId() != null) {
      session = sessionFactory.getOrCreateSession(httpRequest);
    }
    SecurityTokenHolder savedToken = null;
    if (session != null) {
      savedToken = (SecurityTokenHolder) session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
    }
    if (savedToken != null && savedToken.getPrincipals() != null) {
      PrincipalCollection principals = (PrincipalCollection) savedToken.getPrincipals();
      OidcCredentials credentials =
          (OidcCredentials)
              principals
                  .byType(SecurityAssertion.class)
                  .stream()
                  .filter(sa -> SecurityAssertionJwt.JWT_TOKEN_TYPE.equals(sa.getTokenType()))
                  .map(SecurityAssertion::getToken)
                  .findFirst()
                  .orElse(null);
      if (credentials != null && credentials.getIdToken() != null) {
        OidcAuthenticationToken oidcAuthenticationToken =
            new OidcAuthenticationToken(principals, request.getRemoteAddr());
        handlerResult.setToken(oidcAuthenticationToken);
        handlerResult.setStatus(HandlerResult.Status.COMPLETED);
        return handlerResult;
      } else {
        LOGGER.error("ID TOKEN NULL. Credentials: {}", credentials);
        session.invalidate();
        handlerResult.setStatus(HandlerResult.Status.NO_ACTION);
      }
    }

    J2ESessionStore sessionStore = new J2ESessionStore();

    J2EContext j2EContext =
        new J2EContext(httpRequest, ((HttpServletResponse) response), sessionStore);

    // haven't seen this request, so redirect
    StringBuffer requestURL = httpRequest.getRequestURL();
    requestURL.append(
        httpRequest.getQueryString() == null ? "" : "?" + httpRequest.getQueryString());
    OidcCredentials credentials = null;
    try {
      if (handlerConfiguration.getOidcClient() != null) {
        handlerConfiguration.getOidcClient().setCallbackUrl(requestURL.toString());
        handlerConfiguration
            .getOidcClient()
            .setCallbackUrlResolver(new QueryParameterCallbackUrlResolver());
        handlerConfiguration.getOidcClient().init();

        OidcExtractor oidcExtractor =
            new OidcExtractor(
                handlerConfiguration.getOidcConfiguration(), handlerConfiguration.getOidcClient());
        credentials = oidcExtractor.extract(j2EContext);
      } else {
        LOGGER.error("OIDC HANDLER NOT CONFIGURED.");
        handlerResult.setStatus(HandlerResult.Status.NO_ACTION);
        return handlerResult;
      }
    } catch (TechnicalException e) {
      // ignore
    }

    // Authorization code flow
    if (handlerConfiguration.getOidcConfiguration().getResponseType() != null
        && handlerConfiguration.getOidcConfiguration().getResponseType().equals("code")
        && httpRequest.getParameter("code") != null) {

      OidcAuthenticator authenticator =
          new OidcAuthenticator(
              handlerConfiguration.getOidcConfiguration(), handlerConfiguration.getOidcClient());
      authenticator.validate(credentials, j2EContext);
    }

    if (credentials != null) {
      // we've seen this request before, so process it
      SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
      principalCollection.add(new SecurityAssertionJwt(credentials), "default");
      OidcAuthenticationToken oidcAuthenticationToken =
          new OidcAuthenticationToken(principalCollection, request.getRemoteAddr());
      handlerResult.setToken(oidcAuthenticationToken);
      handlerResult.setStatus(HandlerResult.Status.COMPLETED);
      String requestedUrl =
          (String) j2EContext.getSessionStore().get(j2EContext, Pac4jConstants.REQUESTED_URL);
      try {
        ((HttpServletResponse) response).sendRedirect(requestedUrl);
      } catch (IOException e) {
        // ignore
      }
    } else if (handlerConfiguration.getOidcClient() != null) {
      j2EContext
          .getSessionStore()
          .set(j2EContext, Pac4jConstants.REQUESTED_URL, requestURL.toString());

      HttpAction redirect = handlerConfiguration.getOidcClient().redirect(j2EContext);
    }
    //    }

    return handlerResult;
  }

  private void addSecurityToken(HttpSession session, OidcCredentials token) {
    SecurityTokenHolder holder =
        (SecurityTokenHolder)
            session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY);

    holder.setPrincipals(token);
  }

  private Object getSecurityToken(HttpSession session) {
    if (session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY) == null) {
      LOGGER.debug("Security token holder missing from session. New session created improperly.");
      return null;
    }

    SecurityTokenHolder tokenHolder =
        ((SecurityTokenHolder)
            session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY));

    PrincipalCollection principalCollection = (PrincipalCollection) tokenHolder.getPrincipals();

    if (principalCollection != null) {
      Collection<SecurityAssertion> assertion = principalCollection.byType(SecurityAssertion.class);
      return assertion;
    }

    return null;
  }

  // end hack

  private boolean userAgentIsNotBrowser(HttpServletRequest httpRequest) {
    String userAgentHeader = httpRequest.getHeader("User-Agent");
    // basically all browsers support the "Mozilla" way of operating, so they all have "Mozilla"
    // in the string. I just added the rest in case that ever changes for existing browsers.
    // New browsers should contain "Mozilla" as well, though.
    return userAgentHeader == null
        || !(userAgentHeader.contains("Mozilla")
            || userAgentHeader.contains("Safari")
            || userAgentHeader.contains("OPR")
            || userAgentHeader.contains("MSIE")
            || userAgentHeader.contains("Edge")
            || userAgentHeader.contains("Chrome"));
  }

  @Override
  public HandlerResult handleError(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
      throws AuthenticationException {
    HandlerResult result = new HandlerResult(HandlerResult.Status.NO_ACTION, null);
    result.setSource(SOURCE);
    LOGGER.debug("In error handler for oidc - no action taken.");
    return result;
  }

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }
}
