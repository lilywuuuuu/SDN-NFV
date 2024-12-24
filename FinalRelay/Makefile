CONTAINER=h1 h2 R1 R2

define link_netns
	mkdir -p /var/run/netns
	for cname in $(CONTAINER); do \
		pid=$$(docker inspect -f '{{.State.Pid}}' $$cname); \
		sudo ln -sfT /proc/$$pid/ns/net /var/run/netns/$$cname; \
	done
endef

ID = 07
deploy:
	docker compose up -d
	$(call link_netns)

	# setup ovs1 and ovs2
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14
	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14
	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.1:6653
	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.1:6653

	# add ovs1 ports
	sudo ovs-docker add-port ovs1 r1onos R1 --ipaddress=192.168.100.3/24
	sudo ovs-docker add-port ovs1 r1r2 R1 --ipaddress=192.168.63.1/24
	sudo ovs-docker add-port ovs1 r1h1 R1 --ipaddress=172.16.$(ID).69/24
	sudo ovs-docker add-port ovs1 r1ta R1 --ipaddress=192.168.70.$(ID)/24
	sudo ovs-docker add-port ovs1 r2all R2 --ipaddress=192.168.63.2/24
    sudo ovs-docker add-port ovs1 6r1r2 R1 --ipaddress=fd63::1/64
    sudo ovs-docker add-port ovs1 6r1h1 R1 --ipaddress=2a0b:4e07:c4:1$(ID)::69/64
    sudo ovs-docker add-port ovs1 6r1ta R1 --ipaddress=fd70::$(ID)/64
    sudo ovs-docker add-port ovs1 6r2all R2 --ipaddress=fd63::2/64

	# add ovs2 ports
	sudo ovs-docker add-port ovs2 h1all h1 --ipaddress=172.16.$(ID).2/24
	sudo ovs-docker add-port ovs2 6h1all h1 --ipaddress=2a0b:4e07:c4:1$(ID)::2/64
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:local_ip=192.168.61.$(ID) options:remote_ip=192.168.60.$(ID)
	
	# link h1 to R1
	docker exec -it h1 ip route add default via 172.16.$(ID).69
	docker exec -it h1 ip -6 route add default via 2a0b:4e07:c4:$(ID)::69

	# link onos and ovs2
	sudo ip link add vethos2 type veth peer name veths2o
	sudo ovs-vsctl add-port ovs2 veths2o
	sudo ip link set vethos2 up
	sudo ip link set veths2o up
	sudo ip addr add 192.168.100.1/24 dev vethos2

	# link ovs1 and ovs2
	sudo ip link add veths1s2 type veth peer name veths2s1
	sudo ovs-vsctl add-port ovs1 veths1s2
	sudo ovs-vsctl add-port ovs2 veths2s1
	sudo ip link set veths1s2 up
	sudo ip link set veths2s1 up

	# link R2 to h2
	sudo ip link add vethr2h2 type veth peer name vethh2r2
	sudo ip link set vethr2h2 netns R2
	sudo ip link set vethh2r2 netns h2
	sudo ip netns exec R2 ip link set vethr2h2 up
	sudo ip netns exec h2 ip link set vethh2r2 up
	sudo ip netns exec R2 ip addr add 172.17.$(ID).1/24 dev vethr2h2
	sudo ip netns exec h2 ip addr add 172.17.$(ID).2/24 dev vethh2r2
	sudo ip netns exec R2 ip -6 addr add 2a0b:4e07:c4:1$(ID)::1/64 dev vethr2h2
	sudo ip netns exec h2 ip -6 addr add 2a0b:4e07:c4:1$(ID)::2/64 dev vethh2r2
	docker exec -it h2 ip route add default via 172.17.$(ID).1
	docker exec -it h2 ip -6 route add default via 2a0b:4e07:c4:1$(ID)::1


clean:
	sudo ovs-vsctl del-controller ovs1 || true
	sudo ovs-vsctl del-controller ovs2 || true
	sudo ovs-vsctl del-br ovs1 || true
	sudo ovs-vsctl del-br ovs2 || true

	docker compose down

	sudo ip l del vethos2 || true
	sudo ip l del veths2o || true
	sudo ip l del veths1s2 || true
	sudo ip l del veths2s1 || true
	sudo ip l del vethr2h2 || true
	sudo ip l del vethh2r2 || true

	for cname in $(CONTAINER); do \
		sudo ip netns delete $$cname || true; \
	done

	docker network prune -f