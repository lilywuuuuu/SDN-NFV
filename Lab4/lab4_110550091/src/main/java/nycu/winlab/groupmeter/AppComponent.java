package nycu.winlab.groupmeter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.PortNumber;

import org.onosproject.net.group.Group;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;

import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterId;

import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Collection;

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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private GroupMeterIntentProcessor processor = new GroupMeterIntentProcessor();
    private int flowPriority = 50000;
    private ApplicationId appId;
    private ConnectPoint h1, h2;
    private MacAddress mac1, mac2;
    private Ip4Address ip1, ip2;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.groupmeter");

        // config listener
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // packet processor
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // remove flowrule installed by app
        flowRuleService.removeFlowRulesById(appId);

        // remove listerner
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);

        // remove packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule installed for packet-in
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
                h1 = ConnectPoint.deviceConnectPoint(config.host1());
                h2 = ConnectPoint.deviceConnectPoint(config.host2());
                mac1 = MacAddress.valueOf(config.mac1());
                mac2 = MacAddress.valueOf(config.mac2());
                ip1 = Ip4Address.valueOf(config.ip1());
                ip2 = Ip4Address.valueOf(config.ip2());
                if (config != null) {
                    log.info("ConnectPoint_h1: {}, ConnectPoint_h2: {}", h1, h2);
                    log.info("MacAddress_h1: {}, MacAddress _h2: {}", mac1, mac2);
                    log.info("IpAddress_h1: {}, IpAddress_h2: {}", ip1, ip2);
                }
                // group entry & flowrule for s1
                handleGroup(h1.deviceId());

                // meter entry & flowrule for s4
                handleMeter(DeviceId.deviceId("of:0000000000000004"));
            }
        }

        private void handleGroup(DeviceId devId) {
            // bucket 1: outPort = 2 and watchPort = 2
            TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(2))
                    .build();
            GroupBucket bucket1 = DefaultGroupBucket.createFailoverGroupBucket(
                    treatment1, PortNumber.portNumber(2), GroupId.valueOf(0));

            // bucket 2: outPort = 3 and watchPort = 3
            TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(3))
                    .build();
            GroupBucket bucket2 = DefaultGroupBucket.createFailoverGroupBucket(
                    treatment2, PortNumber.portNumber(3), GroupId.valueOf(0));

            GroupBuckets buckets = new GroupBuckets(Arrays.asList(bucket1, bucket2));
            GroupDescription groupDescription = new DefaultGroupDescription(
                    devId, GroupDescription.Type.FAILOVER, buckets);

            groupService.addGroup(groupDescription);
            Group group = groupService.getGroups(devId).iterator().next();

            // add flowrule
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchInPort(PortNumber.portNumber(1))
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .group(group.id())
                    .build();

            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(devId)
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(flowPriority)
                    .makePermanent()
                    .fromApp(appId)
                    .build();

            flowRuleService.applyFlowRules(flowRule);
            log.info("Flow rule installed on device {} with groupID {}", devId, group.id());
        }

        private void handleMeter(DeviceId devId) {
            // create a drop band
            Band dropBand = DefaultBand.builder()
                    .ofType(Band.Type.DROP)
                    .withRate(512) // Rate in KB per second
                    .burstSize(1024) // Burst size
                    .build();
            Collection<Band> bands = Collections.singletonList(dropBand);

            MeterRequest meterRequest = DefaultMeterRequest.builder()
                    .forDevice(devId)
                    .withUnit(Meter.Unit.KB_PER_SEC)
                    .withBands(bands)
                    .burst() // set burst to true
                    .fromApp(appId)
                    .add();

            Meter meter = meterService.submit(meterRequest);

            // add flowrule
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(mac1)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(2))
                    .meter(meter.id())
                    .build();

            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(devId)
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(flowPriority)
                    .makePermanent()
                    .fromApp(appId)
                    .build();

            flowRuleService.applyFlowRules(flowRule);
            log.info("Flow rule installed on device {} with meterID {}", devId, meter.id());
        }
    }

    private class GroupMeterIntentProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled())
                return;

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null)
                return;

            ConnectPoint srcCP = pkt.receivedFrom();
            DeviceId recDevId = srcCP.deviceId();
            PortNumber recPort = srcCP.port();

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) { // deal with ARP packet
                log.info("ARP packet");
                ARP arpPkt = (ARP) ethPkt.getPayload();
                if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
                    Ip4Address dstIp = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
                    MacAddress dstMac = MacAddress.valueOf(arpPkt.getTargetHardwareAddress());
                    Ethernet arpReply = ARP.buildArpReply(dstIp, dstMac, ethPkt);
                    packetOut(ByteBuffer.wrap(arpReply.serialize()), recDevId, recPort);
                }
            } else { // install intent service for IPv4 packet
                log.info("IPv4 packet");
                IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
                int dstIP = ipv4Pkt.getDestinationAddress();
                FilteredConnectPoint ingress = new FilteredConnectPoint(srcCP);
                FilteredConnectPoint egress1 = new FilteredConnectPoint(h1);
                FilteredConnectPoint egress2 = new FilteredConnectPoint(h2);

                // intent service for h2 to h1
                if (dstIP == ip1.toInt()) {
                    handleIntent(srcCP, h1, mac1, ingress, egress1);
                    packetOut(pkt.unparsed(), h1.deviceId(), h1.port());
                }
                // intent service for (s2 or s4) to h2
                else if (dstIP == ip2.toInt()) {
                    handleIntent(srcCP, h2, mac2, ingress, egress2);
                    packetOut(pkt.unparsed(), h2.deviceId(), h2.port());
                }
            }
        }

        private void packetOut(ByteBuffer pkt, DeviceId recDevId, PortNumber recPort) {
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(recPort)
                    .build();
            OutboundPacket packet = new DefaultOutboundPacket(recDevId, treatment, pkt);
            packetService.emit(packet);
        }

        private void handleIntent(ConnectPoint srcCP, ConnectPoint dstCP, MacAddress matchMac,
                FilteredConnectPoint ingress, FilteredConnectPoint egress) {

            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthDst(matchMac)
                    .build();

            PointToPointIntent intent = PointToPointIntent.builder()
                    .filteredIngressPoint(ingress)
                    .filteredEgressPoint(egress)
                    .selector(selector)
                    .priority(flowPriority)
                    .appId(appId)
                    .build();

            intentService.submit(intent);
            log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted.",
                    srcCP.deviceId(), srcCP.port(), dstCP.deviceId(), dstCP.port());
        }
    }
}
