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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;

import org.onlab.packet.ARP;
// import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
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
    // private GroupMeterProcessor processor = new GroupMeterProcessor();

    private final ConfigFactory<ApplicationId, HostConfig> factory = new ConfigFactory<ApplicationId, HostConfig>(
            APP_SUBJECT_FACTORY, HostConfig.class, "informations") {
        @Override
        public HostConfig createConfig() {
            return new HostConfig();
        }
    };

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ConnectPoint host1, host2;
    private MacAddress mac1, mac2;
    private Ip4Address ip1, ip2;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.groupmeter");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private class HostConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(HostConfig.class)) {
                HostConfig config = cfgService.getConfig(appId, HostConfig.class);
                host1 = ConnectPoint.deviceConnectPoint(config.host1());
                host2 = ConnectPoint.deviceConnectPoint(config.host2());
                mac1 = MacAddress.valueOf(config.mac1());
                mac2 = MacAddress.valueOf(config.mac2());
                ip1 = Ip4Address.valueOf(config.ip1());
                ip2 = Ip4Address.valueOf(config.ip2());
                if (config != null) {
                    log.info("ConnectPoint_h1: {}, ConnectPoint_h2: {}", host1, host2);
                    log.info("MacAddress_h1: {}, MacAddress_h2: {}", mac1, mac2);
                    log.info("IpAddress_h1: {}, IpAddress_h2: {}", ip1, ip2);
                }

                // create s1's Buckets and Group
                List<GroupBucket> buckets = new ArrayList<>();
                TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.portNumber(2)).build();
                GroupBucket groupBucket1 = DefaultGroupBucket.createFailoverGroupBucket(
                        treatment1, PortNumber.portNumber(2), GroupId.valueOf(0));
                buckets.add(groupBucket1);
                TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.portNumber(3)).build();
                GroupBucket groupBucket2 = DefaultGroupBucket.createFailoverGroupBucket(
                        treatment2, PortNumber.portNumber(3), GroupId.valueOf(0));
                buckets.add(groupBucket2);

                GroupBuckets groupBuckets = new GroupBuckets(buckets);
                GroupDescription groupDescription = new DefaultGroupDescription(
                        host1.deviceId(), GroupDescription.Type.FAILOVER, groupBuckets);
                groupService.addGroup(groupDescription);
                Group group = groupService.getGroups(host1.deviceId()).iterator().next();
                GroupId groupId = group.id();

                // install flow rule on s1
                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
                selectorBuilder.matchInPort(PortNumber.portNumber(1)).matchEthType(Ethernet.TYPE_IPV4);
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .group(groupId).build();

                FlowRule flowRule = DefaultFlowRule.builder()
                        .withSelector(selectorBuilder.build())
                        .withTreatment(treatment)
                        .forDevice(host1.deviceId())
                        .withPriority(50000)
                        .makePermanent()
                        .fromApp(appId)
                        .build();
                flowRuleService.applyFlowRules(flowRule);

                // create meter entry for s4
                Collection<Band> bands = new ArrayList<>();
                Band band = DefaultBand.builder()
                        .ofType(Band.Type.DROP)
                        .burstSize(1024)
                        .withRate(512)
                        .build();
                bands.add(band);

                MeterRequest meterRequest = DefaultMeterRequest.builder()
                        .forDevice(DeviceId.deviceId("of:0000000000000004"))
                        .burst()
                        .withUnit(Meter.Unit.KB_PER_SEC)
                        .withBands(bands)
                        .fromApp(appId)
                        .add();
                Meter meter = meterService.submit(meterRequest);

                TrafficSelector.Builder meterSelectorBuilder = DefaultTrafficSelector.builder();
                selectorBuilder.matchEthSrc(mac1);
                TrafficTreatment meterTreatment = DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.portNumber(2))
                        .meter(meter.id())
                        .build();
                FlowRule flowRule2 = DefaultFlowRule.builder()
                        .forDevice(DeviceId.deviceId("of:0000000000000004"))
                        .withSelector(meterSelectorBuilder.build())
                        .withTreatment(meterTreatment)
                        .makePermanent()
                        .withPriority(60000)
                        .fromApp(appId)
                        .build();
                flowRuleService.applyFlowRules(flowRule2);

            }
        }
    }

    private class ProxyArpProcessor implements PacketProcessor {

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

            ConnectPoint recConnectPoint = pkt.receivedFrom();
            DeviceId recDevId = recConnectPoint.deviceId();
            PortNumber recPort = recConnectPoint.port();

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                log.info("arp");
                ARP arpPayload = (ARP) ethPkt.getPayload();
                Ip4Address dstIp4Address = Ip4Address.valueOf(arpPayload.getTargetProtocolAddress());
                if (arpPayload.getOpCode() == ARP.OP_REQUEST) {
                    MacAddress targetMac = mac1;
                    if (dstIp4Address.toInt() == ip2.toInt()) {
                        targetMac = mac2;
                    }
                    Ethernet arpPacket = ARP.buildArpReply(dstIp4Address, targetMac, ethPkt);
                    packetOut(recDevId, recPort, ByteBuffer.wrap(arpPacket.serialize()));
                }
            } else {
                log.info("not arp");
                // install intent
                IPv4 ipv4Payload = (IPv4) ethPkt.getPayload();
                int dstIp4Address = ipv4Payload.getDestinationAddress();
                if (dstIp4Address == ip1.toInt()) {
                    FilteredConnectPoint ingressConnectPoint = new FilteredConnectPoint(recConnectPoint);
                    FilteredConnectPoint exgressConnectPoint = new FilteredConnectPoint(host1);
                    log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted. ",
                            recConnectPoint.deviceId(), recConnectPoint.port(), host1.deviceId(), host1.port());
                    TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
                    selectorBuilder.matchEthDst(mac1);
                    PointToPointIntent pointToPointIntent = PointToPointIntent.builder()
                            .filteredIngressPoint(ingressConnectPoint)
                            .filteredEgressPoint(exgressConnectPoint)
                            .selector(selectorBuilder.build())
                            .priority(55000)
                            .appId(appId)
                            .build();
                    intentService.submit(pointToPointIntent);
                    packetOut(host1.deviceId(), host1.port(), pkt.unparsed());
                } else if (dstIp4Address == ip2.toInt()) {
                    FilteredConnectPoint ingressConnectPoint = new FilteredConnectPoint(recConnectPoint);
                    FilteredConnectPoint exgressConnectPoint = new FilteredConnectPoint(host2);
                    TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
                    selectorBuilder.matchEthDst(mac2);
                    PointToPointIntent pointToPointIntent = PointToPointIntent.builder()
                            .filteredIngressPoint(ingressConnectPoint)
                            .filteredEgressPoint(exgressConnectPoint)
                            .selector(selectorBuilder.build())
                            .priority(55000)
                            .appId(appId)
                            .build();
                    intentService.submit(pointToPointIntent);
                    packetOut(host2.deviceId(), host2.port(), pkt.unparsed());
                }
            }
        }
    }

    private void packetOut(DeviceId targetDeviceId, PortNumber portNumber, ByteBuffer pktData) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber).build();
        OutboundPacket outboundPacket = new DefaultOutboundPacket(targetDeviceId, treatment, pktData);
        packetService.emit(outboundPacket);
    }
}
