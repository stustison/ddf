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
package org.codice.ddf.security.filter.login;

import ddf.security.SecurityConstants;
import ddf.security.Subject;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.http.SessionFactory;
import ddf.security.service.SecurityManager;
import ddf.security.service.SecurityServiceException;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.lang.StringUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.codice.ddf.platform.filter.AuthenticationException;
import org.codice.ddf.platform.filter.AuthenticationFailureException;
import org.codice.ddf.platform.filter.FilterChain;
import org.codice.ddf.platform.filter.SecurityFilter;
import org.codice.ddf.platform.util.XMLUtils;
import org.codice.ddf.security.handler.api.BaseAuthenticationToken;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.policy.context.ContextPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Servlet filter that exchanges all incoming tokens for a SAML assertion via an STS. */
public class LoginFilter implements SecurityFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(LoginFilter.class);

  private static final ThreadLocal<DocumentBuilder> BUILDER =
      new ThreadLocal<DocumentBuilder>() {
        @Override
        protected DocumentBuilder initialValue() {
          try {
            return XML_UTILS.getSecureDocumentBuilder(true);
          } catch (ParserConfigurationException ex) {
            // This exception should not happen
            throw new IllegalArgumentException("Unable to create new DocumentBuilder", ex);
          }
        }
      };

  private static final XMLUtils XML_UTILS = XMLUtils.getInstance();

  private static final String DDF_AUTHENTICATION_TOKEN = "ddf.security.token";

  private SecurityManager securityManager;

  private SessionFactory sessionFactory;

  public LoginFilter() {
    super();
  }

  @Override
  public void init() {
    LOGGER.debug("Starting LoginFilter.");
  }

  /**
   * Gets token, resolves token references, and calls the security manager to get a Subject
   *
   * @param request
   * @param response
   * @param chain
   * @throws IOException
   * @throws ServletException
   */
  @Override
  public void doFilter(
      final ServletRequest request, final ServletResponse response, final FilterChain chain)
      throws IOException, AuthenticationException {
    LOGGER.debug("Performing doFilter() on LoginFilter");
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    // Skip filter if no authentication policy
    if (request.getAttribute(ContextPolicy.NO_AUTH_POLICY) != null) {
      LOGGER.debug("NO_AUTH_POLICY header was found, skipping login filter.");
      chain.doFilter(request, response);
      return;
    }

    // grab token from httpRequest
    BaseAuthenticationToken token;
    Object ddfAuthToken = httpRequest.getAttribute(DDF_AUTHENTICATION_TOKEN);
    if (ddfAuthToken instanceof HandlerResult) {
      token = ((HandlerResult) ddfAuthToken).getToken();
    } else {
      LOGGER.debug("Could not attach subject to http request.");
      return;
    }

    // if token is a reference (eg, JESSSIONID), replace with stored credentials
    boolean firstLogin = true;
    if (token.isReference()) {
      token.setRetrievedFromReference(true);
      Object savedToken = resolveReference(token, httpRequest);
      if (savedToken != null) {
        firstLogin = false;
        token.replaceReference(savedToken);
      }
      // ensure that the token now has credentials
      if (token.isReference()) {
        String msg = "Missing or invalid assertion for provided reference.";
        LOGGER.debug(msg);
        throw new AuthenticationFailureException(msg);
      }
    } else {
      // if it's not a reference, attach x509certs and other httpRequest info to be verified in the
      // shiro realms
      token.setRetrievedFromReference(false);
      token.setX509Certs(
          (X509Certificate[]) httpRequest.getAttribute("javax.servlet.request.X509Certificate"));
      token.setRequestURI(httpRequest.getRequestURI());
    }

    // get subject from the token
    Subject subject;
    try {
      subject = securityManager.getSubject(token);
    } catch (SecurityServiceException e) {
      LOGGER.debug("Error getting subject from a Shiro realm", e);
      return;
    }

    // check that security manager was able to resolve a subject
    if (subject == null) {
      LOGGER.debug("Could not attach subject to http request.");
      return;
    }

    // subject is now resolved, perform request as that subject
    httpRequest.setAttribute(SecurityConstants.SECURITY_SUBJECT, subject);
    LOGGER.debug(
        "Now performing request as user {} for {}",
        subject.getPrincipal(),
        StringUtils.isNotBlank(httpRequest.getContextPath())
            ? httpRequest.getContextPath()
            : httpRequest.getServletPath());
    subject.execute(
        () -> {
          PrivilegedExceptionAction<Void> action =
              () -> {
                chain.doFilter(request, response);
                return null;
              };
          SecurityAssertion securityAssertion =
              subject.getPrincipals().oneByType(SecurityAssertion.class);
          if (null != securityAssertion) {
            HashSet emptySet = new HashSet();
            javax.security.auth.Subject javaSubject =
                new javax.security.auth.Subject(
                    true, securityAssertion.getPrincipals(), emptySet, emptySet);
            httpRequest.setAttribute(SecurityConstants.SECURITY_JAVA_SUBJECT, javaSubject);
            javax.security.auth.Subject.doAs(javaSubject, action);
          } else {
            LOGGER.debug("Subject had no security assertion.");
          }
          return null;
        });
  }

  private Object resolveReference(BaseAuthenticationToken token, HttpServletRequest httpRequest) {
    if (token.isReference()) {
      LOGGER.trace("Converting reference to assertion");
      Object sessionTokenHolder =
          httpRequest.getSession(false).getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
      if (LOGGER.isTraceEnabled()) {
        LOGGER.trace(
            "Http Session assertion - class: {}  loader: {}",
            sessionTokenHolder.getClass().getName(),
            sessionTokenHolder.getClass().getClassLoader());
        LOGGER.trace(
            "SecurityToken class: {}  loader: {}",
            SecurityToken.class.getName(),
            SecurityToken.class.getClassLoader());
      }
      try {
        return ((SecurityTokenHolder) sessionTokenHolder).getSecurityToken(token.getRealm());
      } catch (ClassCastException e) {
        httpRequest.getSession(false).invalidate();
      }
    }
    return null;
  }

  public void setSecurityManager(SecurityManager securityManager) {
    this.securityManager = securityManager;
  }

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }

  @Override
  public void destroy() {
    LOGGER.debug("Destroying log in filter");
    BUILDER.remove();
  }
}
