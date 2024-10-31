/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.groupmeter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Sample Network Configuration Service Application. **/
@Component(immediate = true)
public class AppComponent {

  private final Logger log = LoggerFactory.getLogger(getClass());
  private final HostConfigListener cfgListener = new HostConfigListener();


  private final ConfigFactory<ApplicationId, HostConfig> factory = new ConfigFactory<ApplicationId, HostConfig>(
      APP_SUBJECT_FACTORY, HostConfig.class, "informations") {
    @Override
    public HostConfig createConfig() {
      return new HostConfig();
    }
  };

  private ApplicationId appId;

  @Reference(cardinality = ReferenceCardinality.MANDATORY)
  protected NetworkConfigRegistry cfgService;

  @Reference(cardinality = ReferenceCardinality.MANDATORY)
  protected CoreService coreService;

  @Activate
  protected void activate() {
    appId = coreService.registerApplication("nycu.winlab.groupmeter");
    cfgService.addListener(cfgListener);
    cfgService.registerConfigFactory(factory);
    log.info("Started");
  }

  @Deactivate
  protected void deactivate() {
    cfgService.removeListener(cfgListener);
    cfgService.unregisterConfigFactory(factory);
    log.info("Stopped");
  }

  private class HostConfigListener implements NetworkConfigListener {
    @Override
    public void event(NetworkConfigEvent event) {
      if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
          && event.configClass().equals(HostConfig.class)) {
        HostConfig config = cfgService.getConfig(appId, HostConfig.class);
        if (config != null) {
          log.info("ConnectPoint_h1: {}, ConnectPoint_h2: {}", config.host1(), config.host2());
          log.info("MacAddress_h1: {}, MacAddress _h2: {}", config.mac1(), config.mac2());
          log.info("IpAddress_h1: {}, IpAddress_h2: {}", config.ip1(), config.ip2());
        }
      }
    }
  }
}

