deploy:
	cd topo; \
	sudo ./topo_utils.sh deploy; \
	sleep 60; \
	sudo ./topo_utils.sh gen-config ../vrouter/app-conf.json; \
	cd ../vrouter; \
	onos-app localhost install! target/vrouter-1.0-SNAPSHOT.oar; \
	onos-netcfg localhost app-conf.json;

clean:
	cd topo; \
	sudo ./topo_utils.sh clean