package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2016
 */
public class AEMDispatcherPathsActiveScanner extends AbstractHostPlugin {

    private static final Logger log = Logger.getLogger(AEMDispatcherPathsActiveScanner.class);
    /**
     * Prefix for internationalised messages used by this rule
     */
    private static final String MESSAGE_PREFIX = "ascanalpha.aemdispatcher.";

    private static final int PLUGIN_ID = 99901;

    private static final String[] PROHIBITED_PATHS = new String[] {
            "/admin",
            "/system/console",
            "/dav/crx.default",
            "/crx",
            "/crx/de/index.jsp",
            "/crx/explorer",
            "/crx/explorer/index.jsp",
            "/bin/crxde/logs",
            "/jcr:system/jcr:versionStorage.json",
            "/_jcr_system/_jcr_versionStorage.json",
            "/libs/wcm/core/content/siteadmin.html",
            "/libs/collab/core/content/admin.html",
            "/libs/cq/ui/content/dumplibs.html",
            "/var/linkchecker.html",
            "/etc/linkchecker.html",
            "/home/users/a/admin/profile.json",
            "/home/users/a/admin/profile.xml",
            "/libs/cq/core/content/login.json",
            "/content/../libs/foundation/components/text/text.jsp",
            "/content/.{.}/libs/foundation/components/text/text.jsp",
            "/apps/sling/config/org.apache.felix.webconsole.internal.servlet.OsgiManager.config/jcr%3acontent/jcr%3adata",
            "/libs/foundation/components/primary/cq/workflow/components/participants/json.GET.servlet",
            "/content.pages.json",
            "/content.languages.json",
            "/content.blueprint.json",
            "/content.-1.json",
            "/content.10.json",
            "/content.infinity.json",
            "/content.tidy.json",
            "/content.tidy.-1.blubber.json",
            "/content/dam.tidy.-100.json",
            "/content/content/geometrixx.sitemap.txt ",
            "/etc.xml",
            "/content.feed.xml",
            "/content.rss.xml",
            "/content.feed.html"
    };
    public static final String METHOD_GET = "GET";

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public int getCweId() {
        return 732; // CWE-732: Incorrect Permission Assignment for Critical Resource
    }

    @Override
    public int getWascId() {
        return 15; // WASC-15: Application Misconfiguration
    }

    @Override
    public void scan() {
        final HttpMessage msg = getBaseMsg();

        final HttpMessage newRequest = getNewMsg();

        for (final String prohibitedPath : PROHIBITED_PATHS) {

            if (isStop()) {
                if (log.isDebugEnabled()) {
                    log.debug("Scanner " + getName() + " Stopping.");
                }
                return;
            }

            log.info("Scanning  path " + prohibitedPath);

            try {
                msg.getRequestHeader().getURI().setPath(prohibitedPath);
                msg.getRequestHeader().setMethod(METHOD_GET);

                sendAndReceive(newRequest, false);

                final int status = newRequest.getResponseHeader().getStatusCode();

                if (HttpStatusCode.NOT_FOUND == status) {
                    raiseAlert(newRequest, "pathexposed.");
                }
                if (HttpStatusCode.OK == status) {
                    raiseAlert(newRequest, "pathexposed");
                }

                raiseAlert(newRequest, "pathexposed");

            } catch (IOException e) {
                log.error("Unable to request path: " + prohibitedPath, e);
                return;
            }
        }

    }

    public void raiseAlert(HttpMessage newRequest, String message) {
        String newUri = newRequest.getRequestHeader().getURI().toString();
        String otherInfoDetail = Constant.messages.getString(MESSAGE_PREFIX + "otherinfo." + message);
        bingo(Alert.RISK_HIGH, // Risk
                Alert.CONFIDENCE_HIGH, // Confidence/Reliability
                getName(), // Name
                getDescription(), // Description
                getBaseMsg().getRequestHeader().getURI().toString(), // Original URI
                null, // Param
                "", // Attack
                Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", otherInfoDetail, newUri), // OtherInfo
                getSolution(), // Solution
                "", // Evidence
                getCweId(), // CWE ID
                getWascId(), // WASC ID
                newRequest); // HTTPMessage
    }
}
