package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Set;


/**
 * Selectors are a functional part of Apache Sling URL decomposition. See https://sling.apache.org/documentation/the-sling-engine/url-decomposition.html
 * They are often used in Apache Sling and Adobe AEM implementation.
 * <p>
 * Scans URLs for the occurance of selectors and probes them by injecting XSS locator payloads.
 */
public class SlingSelectorXSSActiveScanner extends AbstractAppPlugin{

    private static Logger log = Logger.getLogger(SlingSelectorXSSActiveScanner.class);

    public static String RSXSS_PREFIX = "zApRSX";

    public static String RSXSS_POSTFIX = "zZ";

    private static final String MESSAGE_PREFIX = "ascanalpha.slingselectorxss.";

    private static final int PLUGIN_ID = 99902;

    @Override
    public void scan() {

        final HttpMessage baseMessage = getBaseMsg().cloneRequest();

        try {
            final String path = baseMessage.getRequestHeader().getURI().getPath();
            final String lastSegment = getLastPathSegment(path);

            if (StringUtils.isNotEmpty(lastSegment)) {

                // TODO: add attackable URL
                final HttpMessage attackMessage = getNewMsg();

                attackMessage.getRequestHeader().getURI().setPath("");
                sendAndReceive(attackMessage, false);
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }


    public List<String> findSelectors(final URI uri){

    }

    public Set<String> addSelectorPayloads(final String url, final int selectorIndex){


        return Collections.EMPTY_SET;
    }


    public String getLastPathSegment(final String path) {
        if (path.length() > 0) {
            final int lastIndexofSlash = path.lastIndexOf("/");
            if (lastIndexofSlash > 0) {
                return path.substring(lastIndexofSlash);
            }
        }
        return path;
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public void init() {
    }


}
