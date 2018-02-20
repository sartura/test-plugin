FROM sysrepo/sysrepo-netopeer2:latest

# set root password for user root
RUN \
      echo "root:root" | chpasswd

RUN \
      apt-get update && apt-get install -y \
      valgrind \
      gdb

RUN \
       apt-get update && apt-get install -y \
       libjson0 \
	   libjson0-dev \
	   lua5.1-dev \
	   lua5.1

# ubox
RUN \
      cd /opt/dev && \
      git clone  git://git.openwrt.org/project/libubox.git && \
      cd libubox && mkdir build && cd build && \
	  git checkout fd57eea9f37e447814afbf934db626288aac23c4 && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" .. && \
	  make -j2 && \
	  make install

# uci
RUN \
      cd /opt/dev && \
	  git clone git://nbd.name/uci.git && \
	  cd uci && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF . && \
	  make -j2 && \
	  make install

# ubus
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/ubus.git && \
      cd ubus && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF . && \
	  make -j2 && \
	  make install

# rpcd
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/rpcd.git && \
      cd rpcd && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DIWINFO_SUPPORT=NO . && \
	  make -j2 && \
	  make install && \
	  mkdir /usr/lib/rpcd && \
	  cp file.so /usr/lib/rpcd

RUN \
      apt-get update && apt-get install -y \
	  libcurl4-openssl-dev

# test plugin
RUN \
      cd /opt/dev && \
	  git clone https://github.com/sartura/test-plugin.git && \
	  cd test-plugin && mkdir build && cd build && \
	  git checkout devel && \
	  cmake .. && \
	  make -j2 && \
	  make install && \
	  sysrepoctl -i -g ../yang/plugin-test@2018-02-20.yang

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
