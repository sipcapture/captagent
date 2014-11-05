![](http://i.imgur.com/3kEIR.png)

CaptAgent Project
=========

The Next-Generation capture agent from Sipcapture's [Homer](https://github.com/sipcapture/homer) Project


### Compile & Install

Download the latest code from our repository and compile it on your system (requires libexpat, libpcap, libtool, automake):
```
  cd /usr/src
  git clone https://code.google.com/p/captagent/ captagent
  cd captagent
  ./build.sh
  ./configure
  make && make install
```
  
#### IMPORTANT: 
If you want to enable SSL transport or Payload-Compression use the following flags *(requires: libssl-dev / openssl-devel )*:

```
  ./configure --enable-ssl --enable-compression
  make && make install
```

Captagent should be now ready. Verify with the following command:

```
# captagent -h
usage: captagent <-vh> <-f config>
   -h  is help/usage
   -v  is version information
   -f  is the config file
   -D  is use specified pcap file instead of a device from the config
   -c  is checkout
   -d  is daemon mode
```

### Configuration
Captagent4 cannot properly function without proper configuration. The following default XML example will be installed in /usr/local/etc/captagent/captagent.xml and ready for customization:  
```
<?xml version="1.0"?>

<document type="captagent/xml">

        <configuration name="core.conf" description="CORE Settings">
          <settings>
            <param name="debug" value="3"/>
            <param name="daemon" value="false"/>
            <param name="pid_file" value="/var/run/captagent.pid"/>
            <param name="path" value="/usr/local/lib/captagent/modules"/>
          </settings>
        </configuration>

        <configuration name="modules.conf" description="Modules">
          <modules>
                <load module="core_hep"/>
                <load module="proto_uni"/>
                <load module="capt_cli"/>
          </modules>
        </configuration>

        <!-- CORE MODULES -->

        <configuration name="core_hep.conf" description="HEP Socket">
          <settings>
            <param name="version" value="3"/>
            <param name="capture-host" value="capture.homercloud.org"/>
            <param name="capture-port" value="9000"/>
            <param name="capture-proto" value="udp"/>
            <param name="capture-id" value="2001"/>
            <param name="capture-password" value="myHep"/>
            <param name="payload-compression" value="false" />
          </settings>
        </configuration>

        <!-- PROTOCOLS -->

        <configuration name="proto_uni.conf" description="UNI Proto Basic capture">
          <settings>
            <param name="port" value="5060"/>
            <!-- <param name="portrange" value="5060-5090"/> -->
            <!--
                use -D flag for pcap import
                use "any" for all interfaces in your system
            -->
            <param name="dev"  value="eth0"/>
            <param name="promisc" value="true"/>
            <!--
                comment it if you want to see all IPProto (tcp/udp)
            -->
            <param name="ip-proto" value="udp"/>
            <param name="proto-type"  value="sip"/>
            <!-- <param name="filter" value="not src port 5099"/> -->
          </settings>
        </configuration>

        <!-- CLI  -->

        <configuration name="capt_cli.conf" description="CLI socket">
          <settings>
            <param name="cli-host" value="localhost"/>
            <param name="cli-port" value="8909"/>
            <param name="cli-password" value="12345"/>
          </settings>
        </configuration>

</document>
```

Adjust based on your needs. Once ready you can run the agent in daemon mode as follows:
```
  captagent -d
```

To start the daemon using a different location use the -f switch
```
  captagent -d -f /path/to/captagent_custom.xml
```

### CLI
If you enabled CLI access in your configuration you can telnet to your captagent and obtain usage statistics as follows:
```
# telnet localhost 8909
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.

Welcome to CLI of Captagent

>stats
Statistic of capt_cli module

Statistic of PROTO_UNI module:
Send packets: [1312]

Statistic of CORE_HEP module:
Send packets: [136]
```

### Modules
By default modules will be installed in /usr/local/lib/captagent/modules

### Support
If you found a bug or issue with the code, please raise an Issue on the project tracker.

If you have specific questions or require professional support please contact us at support@sipcapture.org

