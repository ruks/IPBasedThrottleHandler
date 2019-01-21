package org.wso2.bny.carbon.apimgt.gateway.handlers.sample.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;

/**
 * @scr.component name="org.wso2.bny.carbon.apimgt.gateway.handlers.sample" immediate="true"
 */
public class IPBasedThrottlingComponent {
    private static final Log log = LogFactory.getLog(IPBasedThrottlingComponent.class);

    protected void activate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("IPBasedThrottlingComponent activated");
        }
    }

    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("IPBasedThrottlingComponent deactivated");
        }
    }
}
