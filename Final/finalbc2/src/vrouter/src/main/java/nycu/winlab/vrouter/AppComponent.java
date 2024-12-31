/*
 * Copyright 2023-present Open Networking Foundation
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
package nycu.winlab.vrouter;


//import static org.onlab.util.Tools.defaultOffsetDataTime;
import static org.onlab.util.Tools.get;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.RouteEvent;
import org.onosproject.routeservice.RouteInfo;
import org.onosproject.routeservice.RouteListener;
import org.onosproject.routeservice.RouteService;
import org.onosproject.routeservice.RouteTableId;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry networkConfigRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private VRouterPacketProcessor processor = new VRouterPacketProcessor();

    private final VRouterListener vRouterListener = new VRouterListener();

    private ApplicationId appId;

    private List<String> ipv4FrrIP;
    private List<String> ipv6FrrIP;
    private List<String> frrMacAddress;
    
    private List<String> ipv4PeerIP;
    private List<String> ipv6PeerIP;
    MacAddress virtualMac = MacAddress.valueOf("00:00:00:00:00:02");

    @Activate
    protected void activate() {

        appId = coreService.registerApplication("nycu.sdnfv.vrouter");
        log.info("Started");

        packetService.addProcessor(processor, PacketProcessor.director(1));
        routeService.addListener(vRouterListener);
        ipv4FrrIP =  new ArrayList<>();
        ipv4FrrIP.add("192.168.70.7");
        ipv4FrrIP.add("192.168.63.1");
        ipv6FrrIP =  new ArrayList<>();
        ipv6FrrIP.add("fd70::7");
        ipv6FrrIP.add("fd63::1");

        frrMacAddress = new ArrayList<>();
        frrMacAddress.add("22:40:06:8b:90:1e");
        frrMacAddress.add("16:15:3d:d9:45:46");
        
        ipv4PeerIP = new ArrayList<>();
        ipv4PeerIP.add("192.168.70.253");
        ipv4PeerIP.add("192.168.63.2");
        ipv6PeerIP = new ArrayList<>();
        ipv6PeerIP.add("fd70::fe");
        ipv6PeerIP.add("fd63::2");
        log.info("appIDd = {}", appId);

        installTransiantRule();
        installIPv6TransiantRule();
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        routeService.removeListener(vRouterListener);
        ipv4FrrIP = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private class VRouterPacketProcessor implements PacketProcessor {

        /**
         * Process the packet
         *
         * @param context content of the incoming message
         */
        @Override
        public void process(PacketContext context) {

            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null || ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                return;
            }

            if (isControlPacket(ethPkt)) {
                return;
            }

            if (ethPkt.getDestinationMAC().isLldp()) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipPayload = (IPv4) ethPkt.getPayload();
                Ip4Address dstIp4Address = Ip4Address.valueOf(ipPayload.getDestinationAddress());
                Ip4Address srcIP4Address = Ip4Address.valueOf(ipPayload.getSourceAddress());
                log.info("Success get Packet!!!");
                log.info("Get from InterfaceService = {}", interfaceService.getInterfaces());
                log.info("Target IPAddress = {}", dstIp4Address);

                if (containInPrefix(IpPrefix.valueOf("172.16.7.0/24"), srcIP4Address)
                    && containInPrefix(IpPrefix.valueOf("172.16.7.0/24"), dstIp4Address)) {
                    log.info("Intra Traffic = {}, = {}", srcIP4Address, dstIp4Address);
                    return;
                }

                if (containInPrefix(IpPrefix.valueOf("172.16.7.0/24"), dstIp4Address)
                    || containOutPrefix(dstIp4Address)) {
                    log.info("Contain in routers");
                    context.block();
                    installExternalRule(context);
                    return;
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipPayload = (IPv6) ethPkt.getPayload();
                Ip6Address dstIp6Address = Ip6Address.valueOf(ipPayload.getDestinationAddress());
                Ip6Address srcIP6Address = Ip6Address.valueOf(ipPayload.getSourceAddress());
                
                if (containInPrefix(IpPrefix.valueOf("ff02::1:ff00:1/104"), dstIp6Address)) {
                    log.info("Solicited-Node Traffic = {}, = {}", srcIP6Address, dstIp6Address);
                    return;
                }
                log.info("Traffic = {}, = {}", srcIP6Address, dstIp6Address);
                if (containInPrefix(IpPrefix.valueOf("2a0b:4e07:c4:7::/64"), srcIP6Address)
                    && containInPrefix(IpPrefix.valueOf("2a0b:4e07:c4:7::/64"), dstIp6Address)) {
                    log.info("Get from InterfaceService = {}", interfaceService.getInterfaces());
                    log.info("Target IPAddress = {}", dstIp6Address);
                    log.info("Intra Traffic = {}, = {}", srcIP6Address, dstIp6Address);
                    return;
                }

                if (containInPrefix(IpPrefix.valueOf("2a0b:4e07:c4:7::/64"), dstIp6Address)
                    || containOutIPv6Prefix(dstIp6Address)) {
                    log.info("Contain in routers");
                    log.info("Get from InterfaceService = {}", interfaceService.getInterfaces());
                    log.info("Target IPAddress = {}", dstIp6Address);
                    context.block();
                    installIPv6ExternalRule(context);
                    return;
                }
            }
            
            return;
        }
    }

    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private void installExternalRule(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipPayload = (IPv4) ethPkt.getPayload();
        Ip4Address srcIP4Address = Ip4Address.valueOf(ipPayload.getSourceAddress());
        Ip4Address targetIP4Address = Ip4Address.valueOf(ipPayload.getDestinationAddress());
        log.info("External to SDN IPDST = {}", targetIP4Address.toString() + "/32");

        if (containInPrefix(IpPrefix.valueOf("172.16.7.0/24"), targetIP4Address)) { // External to SDN
            Host targetHost = hostService.getHostsByIp(targetIP4Address).iterator().next();
            FilteredConnectPoint ingressFilterPoint = new FilteredConnectPoint(pkt.receivedFrom());
            log.info("External to SDN ingress = {}", ingressFilterPoint);
            FilteredConnectPoint egressFilterPoint
                = new FilteredConnectPoint(
                    new ConnectPoint(targetHost.location().deviceId(), targetHost.location().port()));
            log.info("External to SDN egress = {}", egressFilterPoint);

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchIPDst(IpPrefix.valueOf(targetIP4Address.toString() + "/32"))
                .matchEthType(Ethernet.TYPE_IPV4);
            log.info("External to SDN selector = {}", selector.build());
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualMac)
                .setEthDst(targetHost.mac());
            log.info("External to SDN treatment = {}", treatment.build());

            PointToPointIntent pointIntent = PointToPointIntent.builder()
                .appId(appId).priority(200)
                .filteredIngressPoint(ingressFilterPoint).filteredEgressPoint(egressFilterPoint)
                .selector(selector.build())
                .treatment(treatment.build())
                .build();

            intentService.submit(pointIntent);

        } else { // SDN to External            // log.info("RouteEvent = {}", event.toString());

            ResolvedRoute targetResolvedRoute = getResolvedRoute(targetIP4Address); // next hop
            if (targetResolvedRoute != null) {

                FilteredConnectPoint ingressFilterPoint = new FilteredConnectPoint(pkt.receivedFrom());
                log.info("SDN to External ingress = {}", ingressFilterPoint);
                int index = getIndexInIpv4PeerIp(targetResolvedRoute.nextHop());
                MacAddress frrMac = MacAddress.valueOf(frrMacAddress.get(index));
                Host targetRouter = hostService.getHostsByIp(IpAddress.valueOf(ipv4PeerIP.get(index))).iterator().next();
                log.info("get frr ipaddress index {}", index);
                log.info("get host by ip {}: {}", ipv4FrrIP.get(index), hostService.getHostsByIp(IpAddress.valueOf(ipv4FrrIP.get(index))));

                FilteredConnectPoint egressFilterPoint
                = new FilteredConnectPoint(
                    new ConnectPoint(targetRouter.location().deviceId(), targetRouter.location().port()));
                log.info("SDN to External egress = {}", egressFilterPoint);

                TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchIPDst(IpPrefix.valueOf(targetIP4Address.toString() + "/32"))
                    .matchEthType(Ethernet.TYPE_IPV4);
                log.info("SDN to External selector = {}", selector.build());
                TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(frrMac)
                    .setEthDst(targetResolvedRoute.nextHopMac());
                log.info("SDN to External treatment = {}", treatment.build());

                PointToPointIntent pointIntent = PointToPointIntent.builder()
                    .appId(appId).priority(200)
                    .filteredIngressPoint(ingressFilterPoint).filteredEgressPoint(egressFilterPoint)
                    .selector(selector.build())
                    .treatment(treatment.build())
                    .build();

                intentService.submit(pointIntent);
            }
        }

    }
    private void installIPv6ExternalRule(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv6 ipPayload = (IPv6) ethPkt.getPayload();
        Ip6Address srcIP6Address = Ip6Address.valueOf(ipPayload.getSourceAddress());
        Ip6Address targetIP6Address = Ip6Address.valueOf(ipPayload.getDestinationAddress());
        log.info("IPV6 External to SDN IPDST = {}", targetIP6Address.toString() + "/128");

        if (containInPrefix(IpPrefix.valueOf("2a0b:4e07:c4:7::/64"), targetIP6Address)) { // External to SDN
            Host targetHost = hostService.getHostsByIp(targetIP6Address).iterator().next();
            FilteredConnectPoint ingressFilterPoint = new FilteredConnectPoint(pkt.receivedFrom());
            log.info("IPV6 External to SDN ingress = {}", ingressFilterPoint);
            FilteredConnectPoint egressFilterPoint
                = new FilteredConnectPoint(
                    new ConnectPoint(targetHost.location().deviceId(), targetHost.location().port()));
            log.info("IPV6 External to SDN egress = {}", egressFilterPoint);

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchIPv6Dst(IpPrefix.valueOf(targetIP6Address.toString() + "/128"))
                .matchEthType(Ethernet.TYPE_IPV6);
            log.info("IPV6 External to SDN selector = {}", selector.build());
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualMac)
                .setEthDst(targetHost.mac());
            log.info("IPV6 External to SDN treatment = {}", treatment.build());

            PointToPointIntent pointIntent = PointToPointIntent.builder()
                .appId(appId).priority(200)
                .filteredIngressPoint(ingressFilterPoint).filteredEgressPoint(egressFilterPoint)
                .selector(selector.build())
                .treatment(treatment.build())
                .build();

            intentService.submit(pointIntent);

        } else { // SDN to External            // log.info("RouteEvent = {}", event.toString());

            ResolvedRoute targetResolvedRoute = getIPv6ResolvedRoute(targetIP6Address); // next hop
            if (targetResolvedRoute != null) {

                FilteredConnectPoint ingressFilterPoint = new FilteredConnectPoint(pkt.receivedFrom());
                FilteredConnectPoint reverseEgressFilterPoint = new FilteredConnectPoint(pkt.receivedFrom());
                log.info("IPV6 SDN to External ingress = {}", ingressFilterPoint);
                log.info("IPV6 SDN to External ingress = {}", reverseEgressFilterPoint);
                int index = getIndexInIpv6PeerIp(targetResolvedRoute.nextHop());
                Host srcRouter = hostService.getHostsByIp(IpAddress.valueOf(ipv6FrrIP.get(index))).iterator().next();
                Host targetRouter = hostService.getHostsByIp(IpAddress.valueOf(ipv6PeerIP.get(index))).iterator().next();
                Host targetHost = hostService.getHostsByIp(srcIP6Address).iterator().next();
                log.info("IPV6 get frr ipaddress index {}", index);
                log.info("IPV6 get host by ip {}: {}", ipv6FrrIP.get(index), hostService.getHostsByIp(IpAddress.valueOf(ipv6FrrIP.get(index))));

                FilteredConnectPoint egressFilterPoint
                = new FilteredConnectPoint(
                    new ConnectPoint(targetRouter.location().deviceId(), targetRouter.location().port()));
                log.info("IPV6 SDN to External egress = {}", egressFilterPoint);
                FilteredConnectPoint reverseIngressFilterPoint
                = new FilteredConnectPoint(
                    new ConnectPoint(targetRouter.location().deviceId(), targetRouter.location().port()));
                log.info("IPV6 SDN to External egress = {}", reverseIngressFilterPoint);

                TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchIPv6Dst(IpPrefix.valueOf(targetIP6Address.toString() + "/128"))
                    .matchEthType(Ethernet.TYPE_IPV6);
                TrafficSelector.Builder reverseSelector = DefaultTrafficSelector.builder()
                    .matchIPv6Dst(IpPrefix.valueOf(srcIP6Address.toString() + "/128"))
                    .matchEthType(Ethernet.TYPE_IPV6);
                log.info("IPV6 SDN to External selector = {}", selector.build());
                TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(srcRouter.mac())
                    .setEthDst(targetResolvedRoute.nextHopMac());
                TrafficTreatment.Builder reverseTreatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(virtualMac)
                    .setEthDst(targetHost.mac());
                log.info("IPV6 SDN to External treatment = {}", treatment.build());

                PointToPointIntent pointIntent = PointToPointIntent.builder()
                    .appId(appId).priority(50000)
                    .filteredIngressPoint(ingressFilterPoint).filteredEgressPoint(egressFilterPoint)
                    .selector(selector.build())
                    .treatment(treatment.build())
                    .build();
                PointToPointIntent reversePointIntent = PointToPointIntent.builder()
                    .appId(appId).priority(50000)
                    .filteredIngressPoint(reverseIngressFilterPoint).filteredEgressPoint(reverseEgressFilterPoint)
                    .selector(reverseSelector.build())
                    .treatment(reverseTreatment.build())
                    .build();

                intentService.submit(pointIntent);
                intentService.submit(reversePointIntent);
            }
        }

    }

    private void installTransiantRule() {
            Collection<RouteTableId> rTable = routeService.getRouteTables();
            ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
            Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(0));
            ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);
            log.info("CollectionRouteTable = {}", rTable);
            log.info("ArrayListRouteTable = {}", rTableList);
            log.info("CollectionRouteInfo = {}", rinfosC);
            log.info("ArrayListRouteInfo = {}", rinfos);
            // log.info("RouteEvent = {}", event.toString());

            // log.info("InfoArraySize = {}", rinfos.size());
            for (int i = 0; i < rinfos.size(); i++) {
                ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
                Intent existIntent = intentService.getIntent(Key.of(resolvedRoute.prefix().toString(), appId));
                if (existIntent == null) {
                    int index = getIndexInIpv4PeerIp(resolvedRoute.nextHop());
                    MacAddress frrMac = MacAddress.valueOf(frrMacAddress.get(index));
                    MacAddress getFromHostService = hostService.
                        getHostsByIp(resolvedRoute.nextHop()).iterator().next().mac();
                    TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                        .matchIPDst(resolvedRoute.prefix()).matchEthType(Ethernet.TYPE_IPV4);
                    log.info("Selector = {}", selector.build());
                    TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                        .setEthSrc(frrMac)
                        .setEthDst(resolvedRoute.nextHopMac());
                    log.info("Treatment = {}", treatment.build());

                    log.info("Get from HostService = {}", getFromHostService);
                    log.info("Get from RouteServiec, prefix = {}, next hop = {}, next hop mac = {}",
                            resolvedRoute.prefix(), resolvedRoute.nextHop(), resolvedRoute.nextHopMac());
                    
                    ConnectPoint egressPoint = interfaceService.getMatchingInterface(resolvedRoute.nextHop()).connectPoint();
                    FilteredConnectPoint egressFilterPoint = new FilteredConnectPoint(egressPoint);
                    log.info("EgressPoint = {}", egressFilterPoint);

                    Set<FilteredConnectPoint> s = new HashSet<FilteredConnectPoint>();
                    for (int j = 0; j < ipv4FrrIP.size(); j++) {
                        ConnectPoint ingressPoint = interfaceService.
                            getMatchingInterface(Ip4Address.valueOf(ipv4FrrIP.get(j))).connectPoint();
                        if (!egressPoint.equals(ingressPoint)) {
                            s.add(new FilteredConnectPoint(ingressPoint));
                        }
                    }
                    log.info("IngressPoints = {}", s);

                    Key key = Key.of(resolvedRoute.prefix().toString(), appId);

                    MultiPointToSinglePointIntent intent = MultiPointToSinglePointIntent.builder()
                        .appId(appId).key(key)
                        .filteredIngressPoints(s).filteredEgressPoint(egressFilterPoint)
                        .selector(selector.build()).treatment(treatment.build())
                        .build();
                    log.info("Success Build Intent");

                    intentService.submit(intent);
                    log.info("Success Submit Intent");
                }
            }
    }

    private void installIPv6TransiantRule() {
        Collection<RouteTableId> rTable = routeService.getRouteTables();
        ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
        Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(1));
        ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);
        log.info("CollectionRouteTable = {}", rTable);
        log.info("ArrayListRouteTable = {}", rTableList);
        log.info("CollectionRouteInfo = {}", rinfosC);
        log.info("ArrayListRouteInfo = {}", rinfos);
        // log.info("RouteEvent = {}", event.toString());

        // log.info("InfoArraySize = {}", rinfos.size());
        for (int i = 0; i < rinfos.size(); i++) {
            ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
            Intent existIntent = intentService.getIntent(Key.of(resolvedRoute.prefix().toString(), appId));
            if (existIntent == null) {
                int index = getIndexInIpv6PeerIp(resolvedRoute.nextHop());
                MacAddress frrMac = MacAddress.valueOf(frrMacAddress.get(index));
                MacAddress getFromHostService = hostService.
                    getHostsByIp(resolvedRoute.nextHop()).iterator().next().mac();
                TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchIPv6Dst(resolvedRoute.prefix()).matchEthType(Ethernet.TYPE_IPV6);
                log.info("Selector = {}", selector.build());
                TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(frrMac)
                    .setEthDst(resolvedRoute.nextHopMac());
                log.info("Treatment = {}", treatment.build());

                log.info("Get from HostService = {}", getFromHostService);
                log.info("Get from RouteServiec, prefix = {}, next hop = {}, next hop mac = {}",
                        resolvedRoute.prefix(), resolvedRoute.nextHop(), resolvedRoute.nextHopMac());
                
                ConnectPoint egressPoint = interfaceService.getMatchingInterface(resolvedRoute.nextHop()).connectPoint();
                FilteredConnectPoint egressFilterPoint = new FilteredConnectPoint(egressPoint);
                log.info("EgressPoint = {}", egressFilterPoint);

                Set<FilteredConnectPoint> s = new HashSet<FilteredConnectPoint>();
                for (int j = 0; j < ipv6FrrIP.size(); j++) {
                    ConnectPoint ingressPoint = interfaceService.
                        getMatchingInterface(Ip6Address.valueOf(ipv6FrrIP.get(j))).connectPoint();
                    if (!egressPoint.equals(ingressPoint)) {
                        s.add(new FilteredConnectPoint(ingressPoint));
                    }
                }
                log.info("IngressPoints = {}", s);

                Key key = Key.of(resolvedRoute.prefix().toString(), appId);

                MultiPointToSinglePointIntent intent = MultiPointToSinglePointIntent.builder()
                    .appId(appId).key(key)
                    .filteredIngressPoints(s).filteredEgressPoint(egressFilterPoint)
                    .selector(selector.build()).treatment(treatment.build())
                    .build();
                log.info("Success Build Intent");

                intentService.submit(intent);
                log.info("Success Submit Intent");
            }
        }
}

    private ResolvedRoute getResolvedRoute(Ip4Address ip4Address) {
        Collection<RouteTableId> rTable = routeService.getRouteTables();
        ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
        Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(0));
        ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);

        for (int i = 0; i < rinfos.size(); i++) {
            ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
            if (resolvedRoute.prefix().contains(ip4Address)) {
                return resolvedRoute;
            }
        }

        return null;
    }

    private ResolvedRoute getIPv6ResolvedRoute(Ip6Address ip6Address) {
        Collection<RouteTableId> rTable = routeService.getRouteTables();
        ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
        Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(1));
        ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);

        for (int i = 0; i < rinfos.size(); i++) {
            ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
            if (resolvedRoute.prefix().contains(ip6Address)) {
                return resolvedRoute;
            }
        }

        return null;
    }

    private int getIndexInIpv4PeerIp(IpAddress ip4Address) {
        for (int i = 0; i < ipv4PeerIP.size(); i++) {
            log.info("IpPrefix = {}", ip4Address);
            log.info("Prefix contain IP = {}", ipv4PeerIP.get(i));
            log.info("------------------");
            if (ip4Address.toString().equals(ipv4PeerIP.get(i))) {
                return i;
            }
        }

        return 0;
    }

    private int getIndexInIpv6PeerIp(IpAddress ip6Address) {
        for (int i = 0; i < ipv6PeerIP.size(); i++) {
            log.info("IpPrefix = {}", ip6Address);
            log.info("Prefix contain IP = {}", ipv6PeerIP.get(i));
            log.info("------------------");
            if (ip6Address.toString().equals(ipv6PeerIP.get(i))) {
                return i;
            }
        }

        return 0;
    }

    private boolean containInPrefix(IpPrefix ipPrefix, IpAddress ipAddress) {

        if (ipPrefix.contains(ipAddress)) {
            return true;
        }

        return false;
    }

    private boolean containOutPrefix(Ip4Address ip4Address) {

        Collection<RouteTableId> rTable = routeService.getRouteTables();
        ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
        Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(0));
        ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);

        for (int i = 0; i < rinfos.size(); i++) {
            ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
            if (resolvedRoute.prefix().contains(ip4Address)) {
                return true;
            }
        }

        return false;
    }

    private boolean containOutIPv6Prefix(Ip6Address ip6Address) {

        Collection<RouteTableId> rTable = routeService.getRouteTables();
        ArrayList<RouteTableId> rTableList = new ArrayList<RouteTableId>(rTable);
        Collection<RouteInfo> rinfosC = routeService.getRoutes(rTableList.get(1));
        ArrayList<RouteInfo> rinfos = new ArrayList<RouteInfo>(rinfosC);

        for (int i = 0; i < rinfos.size(); i++) {
            ResolvedRoute resolvedRoute = rinfos.get(i).allRoutes().iterator().next();
            if (resolvedRoute.prefix().contains(ip6Address)) {
                return true;
            }
        }

        return false;
    }

    private class VRouterListener implements RouteListener {

        @Override
        public void event(RouteEvent event) {
            installTransiantRule();
            installIPv6TransiantRule();
        }
    }

}