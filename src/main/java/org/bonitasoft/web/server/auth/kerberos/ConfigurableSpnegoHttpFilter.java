/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * Copyright (C) 2018 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.bonitasoft.web.server.auth.kerberos;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bonitasoft.web.server.auth.kerberos.KerberosConfig;
import org.ietf.jgss.GSSException;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoFilterConfig;
import net.sourceforge.spnego.SpnegoHttpFilter;
import net.sourceforge.spnego.SpnegoHttpFilter.Constants;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;
import net.sourceforge.spnego.UserAccessControl;

/**
 * This web application filter is an fork of net.sourceforge.spnego.SpnegoHttpFilter in
 * order load the configuration from a properties file depending on the request content.
 * Due to the final nature of this class we cannot extend it.
 * 
 * @author Anthony Birembaut
 */
public abstract class ConfigurableSpnegoHttpFilter implements Filter {
    
    private static final Logger LOGGER = Logger.getLogger(ConfigurableSpnegoHttpFilter.class.getName());
    
    /** Object for performing Basic and SPNEGO authentication. */
    private transient SpnegoAuthenticator authenticator;
    
    /** Object for performing User Authorization. */
    private transient UserAccessControl accessControl;
    
    /** AuthZ required for every page. */
    private transient String sitewide;
    
    /** Landing page if user is denied authZ access. */
    private transient String page403;
    
    /** directories which should not be authenticated irrespective of filter-mapping. */
    private final transient List<String> excludeDirs = new ArrayList<String>();

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        //Other configuration cannot be retrieved here as it depends on the request
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        Properties spnegoProperties = getSpnegoProperties(httpRequest);
        loadConfig(spnegoProperties);
        // skip authentication if resource is in the list of directories to exclude
        if (exclude(httpRequest.getContextPath(), httpRequest.getServletPath())) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            spnegoDoFilter(servletRequest, servletResponse, filterChain);
        }
    }
	
    protected abstract Properties getSpnegoProperties(HttpServletRequest httpRequest) throws ServletException;

    /**
     * Copy of {@link SpnegoHttpFilter}#init without the first lines regarding the exclude pattern (handled in getKerberosConfig()).
     */
    public void loadConfig(Properties spnegoProperties) throws IOException, ServletException {
        try {
            //customization start
            final KerberosConfig bonitaKerberosConfig = getKerberosConfig(spnegoProperties);
            //customization end
            
            final SpnegoFilterConfig config = SpnegoFilterConfig.getInstance(bonitaKerberosConfig);
            
            //Copy of {@link SpnegoHttpFilter}#init
            // pre-authenticate
            this.authenticator = new SpnegoAuthenticator(config);
            
            // authorization
            if (!spnegoProperties.getProperty("spnego.authz.class", "").isEmpty()) {
                spnegoProperties.put("spnego.server.realm", this.authenticator.getServerRealm());
                this.page403 = spnegoProperties.getProperty("spnego.authz.403", "").trim();
                this.sitewide = spnegoProperties.getProperty("spnego.authz.sitewide", "").trim();
                this.sitewide = (this.sitewide.isEmpty()) ? null : this.sitewide;
                this.accessControl = (UserAccessControl) Class.forName(
                        spnegoProperties.getProperty("spnego.authz.class")).newInstance();
                this.accessControl.init(spnegoProperties);                
            }
        } catch (final LoginException lex) {
            throw new ServletException(lex);
        } catch (final GSSException gsse) {
            throw new ServletException(gsse);
        } catch (final PrivilegedActionException pae) {
            throw new ServletException(pae);
        } catch (final FileNotFoundException fnfe) {
            throw new ServletException(fnfe);
        } catch (final URISyntaxException uri) {
            throw new ServletException(uri);
        } catch (InstantiationException iex) {
            throw new ServletException(iex);
        } catch (IllegalAccessException iae) {
            throw new ServletException(iae);
        } catch (ClassNotFoundException cnfe) {
            throw new ServletException(cnfe);
        }
    }

    protected KerberosConfig getKerberosConfig(Properties spnegoProperties) {
        final KerberosConfig config = new KerberosConfig(spnegoProperties);
        String excludeDirsString = spnegoProperties.getProperty(Constants.EXCLUDE_DIRS);
        if (excludeDirsString != null && excludeDirsString.length() > 0) {
            for (String dir : excludeDirsString.split(",")) {
                this.excludeDirs.add(clean(dir.trim()));
            }
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("excludeDirs=" + this.excludeDirs);
            }
        }
        return config;
    }
    
    /**
     * copy of {@link SpnegoFilterConfig}#clean
     */
    protected static String clean(final String path) {
        
        // assert - more than one char (we do not support ROOT) and no wild card
        if (path.length() < 2 || path.contains("*")) {
            throw new IllegalArgumentException(
                "Invalid exclude.dirs pattern or char(s): " + path);
        }
        
        // ensure that it ends with the slash character
        final String tmp;
        if (path.endsWith("/")) {
            tmp = path;
        } else {
            tmp = path + "/";
        }
        // we want to include the slash character
        return tmp.substring(0, tmp.lastIndexOf('/') + 1);
    }
    
    /**
     * Copy of {@link SpnegoHttpFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}} without the exclude pattern management.
     */
    public void spnegoDoFilter(final ServletRequest request, final ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse) response);

        
        // client/caller principal
        final SpnegoPrincipal principal;
        try {
            principal = this.authenticator.authenticate(httpRequest, spnegoResponse);
        } catch (GSSException gsse) {
            LOGGER.severe("HTTP Authorization Header="
                + httpRequest.getHeader(Constants.AUTHZ_HEADER));
            throw new ServletException(gsse);
        }

        // context/auth loop not yet complete
        if (spnegoResponse.isStatusSet()) {
            return;
        }

        // assert
        if (null == principal) {
            LOGGER.severe("Principal was null.");
            spnegoResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, true);
            return;
        }

        LOGGER.fine("principal=" + principal);
        
        SpnegoHttpServletRequest spnegoRequest = 
                new SpnegoHttpServletRequest(httpRequest, principal, this.accessControl);
                
        // site wide authZ check (if enabled)
        if (!isAuthorized((HttpServletRequest) spnegoRequest)) {
            LOGGER.info("Principal Not AuthoriZed: " + principal);
            if (this.page403.isEmpty()) {
                spnegoResponse.setStatus(HttpServletResponse.SC_FORBIDDEN, true);  
            } else {
                httpRequest.getRequestDispatcher(this.page403).forward(spnegoRequest, spnegoResponse.getResponse());
            }
            return;            
        }
        filterChain.doFilter(spnegoRequest, spnegoResponse);
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Remote user after kerberos authentication: " + spnegoRequest.getRemoteUser());
        }
    }
    
    /**
     * Copy of {@link SpnegoHttpFilter}#isAuthorized}
     */
    protected boolean isAuthorized(final HttpServletRequest request) {
        if (null != this.sitewide && null != this.accessControl
                && !this.accessControl.hasAccess(request.getRemoteUser(), this.sitewide)) {
            return false;
        }
        return true;
    }
    
    /**
     * Copy of {@link SpnegoHttpFilter}#exclude}
     */
    protected boolean exclude(final String contextPath, final String servletPath) {
        // each item in excludeDirs ends with a slash
        final String path = contextPath + servletPath + (servletPath.endsWith("/") ? "" : "/");
        
        for (String dir : this.excludeDirs) {
            if (path.startsWith(dir)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Copy of {@link SpnegoHttpFilter#destroy()}
     */
    @Override
    public void destroy() {
        this.page403 = null;
        this.sitewide = null;
        if (null != this.excludeDirs) {
            this.excludeDirs.clear();
        }
        if (null != this.accessControl) {
            this.accessControl.destroy();
            this.accessControl = null;
        }
        if (null != this.authenticator) {
            this.authenticator.dispose();
            this.authenticator = null;
        }
    }
}
