CONTAINER=h1 h2 R1 R2

define netns
	mkdir -p /var/run/netns
	for cname in $(CONTAINER); do \
	pid=$$(docker inspect -f '{{.State.Pid}}' $$cname); \
	sudo ln -sfT /proc/$$pid/ns/net /var/run/netns/$$cname; \
	done
endef

define create_as_veth
	$(eval $@_C1 = $(1))
	$(eval $@_C2 = $(2))
	$(eval $@_IP1= $(3))
	$(eval $@_IP2= $(4))
	$(eval $@_IP6_1= $(5))
	$(eval $@_IP6_2= $(6))
	$(eval $@_L1=veth${$@_C1}${$@_C2})
	$(eval $@_L2=veth${$@_C2}${$@_C1})
	sudo ip link add ${$@_L1} type veth peer name ${$@_L2}
	sudo ip link set ${$@_L1} netns ${$@_C1}
	sudo ip link set ${$@_L2} netns ${$@_C2}
	sudo ip netns exec ${$@_C1} ip link set ${$@_L1} up
	sudo ip netns exec ${$@_C2} ip link set ${$@_L2} up
	sudo ip netns exec ${$@_C1} ip a a ${$@_IP1} dev ${$@_L1}
	sudo ip netns exec ${$@_C2} ip a a ${$@_IP2} dev ${$@_L2}
	sudo ip netns exec ${$@_C1} ip -6 a a ${$@_IP6_1} dev ${$@_L1}
	sudo ip netns exec ${$@_C2} ip -6 a a ${$@_IP6_2} dev ${$@_L2}
endef

deploy:
	docker compose up -d
	$(call netns)

	for cname in $(CONTAINER); do \
		docker exec -it $$cname sysctl -w net.ipv6.conf.all.disable_ipv6=0; \
		docker exec -it $$cname sysctl -w net.ipv6.conf.default.disable_ipv6=0; \
		docker exec -it $$cname sysctl -w net.ipv6.conf.lo.disable_ipv6=0; \
	done

	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14
	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14
	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.1:6653
	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.1:6653

	sudo ovs-docker add-port ovs1 tonos R1 --ipaddress=192.168.100.3/24
	sudo ovs-docker add-port ovs1 tr2 R1 --ipaddress=192.168.63.1/24
	docker exec -it R1 ip -6 addr add fd63::1/64 dev tr2
	sudo ovs-docker add-port ovs1 tr1 R2 --ipaddress=192.168.63.2/24
	docker exec -it R2 ip -6 addr add fd63::2/64 dev tr1
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.9 options:local_ip=192.168.61.9

	sudo ovs-docker add-port ovs2 tas h1 --ipaddress=172.16.8.2/24
	docker exec -it h1 ip -6 addr add 2a0b:4e07:c4:8::2/64 dev tas
	sudo ovs-docker add-port ovs1 tas R1 --ipaddress=172.16.8.69/24
	docker exec -it R1 ip -6 addr add 2a0b:4e07:c4:8::69/64 dev tas

	# configure routes
	docker exec -it h1 ip route add default via 172.16.8.69
	docker exec -it h1 ip -6 route add default via 2a0b:4e07:c4:8::69

	# veth 192.168.100.1 for onos and ovs2 
	sudo ip link add veth0 type veth peer name veth1
	sudo ovs-vsctl add-port ovs2 veth0
	sudo ip link set veth0 up
	sudo ip link set veth1 up
	sudo ip a add 192.168.100.1/24 dev veth1

	# link ovs1 and ovs2
	sudo ip link add veths1s2 type veth peer name veths2s1
	sudo ovs-vsctl add-port ovs1 veths1s2
	sudo ovs-vsctl add-port ovs2 veths2s1
	sudo ip link set veths1s2 up
	sudo ip link set veths2s1 up

	# link to IXP
	sudo ovs-docker add-port ovs1 tixp R1 --ipaddress=192.168.70.8/24

	# AS1
	@$(call create_as_veth, R2, h2, 172.17.8.1/24, 172.17.8.2/24, 2a0b:4e07:c4:108::1/64, 2a0b:4e07:c4:108::2/64)
	docker exec -it h2 ip r add default via 172.17.8.1
	docker exec -it h2 ip -6 r add default via 2a0b:4e07:c4:108::1

test:

clean:
	sudo ovs-vsctl del-controller ovs1
	sudo ovs-vsctl del-controller ovs2
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	docker compose down
	sudo ip l del veth0
	sudo ip l del veths1s2
	sudo ip l del vethtar1
	@basename -a /sys/class/net/veth* | grep -e '\([Rh][0-9]\)\{2\}' | xargs -I {} ip l del {} 2>/dev/null | true

testclean: