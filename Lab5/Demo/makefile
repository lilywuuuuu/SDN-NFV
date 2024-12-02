IMAGE_NAME = host

# Set up the environment
main:
	docker build -t $(IMAGE_NAME) -f host.Dockerfile .
	docker compose up -d

	sudo ovs-vsctl add-br ovsbr1
	sudo ovs-vsctl set bridge ovsbr1 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr1 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovsbr1 eth2 R1 --ipaddress=172.18.0.2/16
	sudo ovs-docker add-port ovsbr1 eth3 h1 --ipaddress=172.18.0.3/16

	sudo ovs-vsctl add-br ovsbr2
	sudo ovs-vsctl set bridge ovsbr2 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr2 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovsbr2 eth2 R2 --ipaddress=172.19.0.2/16
	sudo ovs-docker add-port ovsbr2 eth3 h2 --ipaddress=172.19.0.3/16

	docker exec h1 ip route add default via 172.18.0.2
	docker exec h2 ip route add default via 172.19.0.2

# Clean up the environment
clean:
	docker compose down
	sudo ovs-vsctl --if-exists del-br ovsbr1
	sudo ovs-vsctl --if-exists del-br ovsbr2