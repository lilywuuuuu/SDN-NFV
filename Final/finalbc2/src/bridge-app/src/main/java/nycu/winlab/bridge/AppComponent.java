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
package nycu.winlab.bridge;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRule;
// import org.onosproject.net.flowobjective.DefaultForwardingObjective;
// import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private ApplicationId appId;
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.bridge");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(4));

        // install a flowrule for packet-in
        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // rec packet-in from new device, create new table for it
            if (bridgeTable.get(recDevId) == null) {
                bridgeTable.put(recDevId, new HashMap<>());
            }


            if (bridgeTable.get(recDevId).get(srcMac) == null) {
                // the mapping of pkt's src mac and receivedfrom port wasn't store in the table of the rec device
                log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                recDevId, srcMac, recPort);
                bridgeTable.get(recDevId).put(srcMac, recPort);
            }

            if (bridgeTable.get(recDevId).get(dstMac) == null) {
                // the mapping of dst mac and forwarding port wasn't store in the table of the rec device
                // log.info("MAC address `{}` is missed on `{}`. Flood the packet.",
                // dstMac, recDevId);
                flood(context);

            } else if (bridgeTable.get(recDevId).get(dstMac) != null) {
                // there is a entry store the mapping of dst mac and forwarding port
                packetOut(context, bridgeTable.get(recDevId).get(dstMac));
                log.info("MAC address `{}` is matched on `{}`. Install a flow rule.",
                dstMac, recDevId);
                installRule(context, srcMac, dstMac);
            }
        }
    }

    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
    }

    private void packetOut(PacketContext context, PortNumber portnumber) {
        context.treatmentBuilder().setOutput(portnumber);
        context.send();
    }

    private void installRule(PacketContext context, MacAddress srcMac, MacAddress dstMac) {
        InboundPacket pkt = context.inPacket();
        DeviceId recDevId = pkt.receivedFrom().deviceId();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthSrc(srcMac).matchEthDst(dstMac);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
        .setOutput(bridgeTable.get(recDevId).get(dstMac)).build();

        // install flow rule
        FlowRule flowRule = DefaultFlowRule.builder()
        .withSelector(selectorBuilder.build())
        .withTreatment(treatment)
        .withPriority(300)
        .withIdleTimeout(30)
        .forDevice(recDevId)
        .fromApp(appId)
        .build();

        // flowObjectiveService.forward(recDevId, forwardingObjective);
        flowRuleService.applyFlowRules(flowRule);
        return;
    }

}