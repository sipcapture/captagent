[![Dependency Status](https://david-dm.org/sipcapture/hep-js.svg)](https://david-dm.org/sipcapture/hep-js)
![npm](https://img.shields.io/npm/dm/hep-js.svg)

<img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/>

# HEP-js
HEP: Javascript/Node implementation of HEP/EEP Encapsulation Protocol


This module provides Node with [HEP/EEP](http://hep.sipcapture.org) packet encapsulation and decapsulation capabilities.

For more information about HEP and SIPCAPTURE Projects, please visit [http://sipcapture.org](http://sipcapture.org)

### Install:
```
npm install hep-js
```


### Example Usage:
```
const HEPjs = require('hep-js');
var hep_encoder = HEPjs.encapsulate(payload,rcinfo); // returns data buffer
var hep_decoder = HEPjs.decapsulate(buffer); // returns JSON Object {payload,rcinfo}

```

#### Example: payload
```
ACK sip:883510000000091@domain.net SIP/2.0
Via: SIP/2.0/UDP 192.168.1.23:5060;rport;branch=z9hG4bK484759904 
From: <sip:somebody@somewhere.net>;tag=412285373 
To: <sip:883510000000091@domain.net>;tag=1d24a28a0bded6c40d31e6db8aab9ac6.4679 
Call-ID: 1003554701 
CSeq: 20 ACK 
Content-Length: 0 
```

#### Example: rcinfo
```
rcinfo = { type: 'HEP',
  version: 3,
  payload_type: 'SIP',
  captureId: '2001',
  capturePass: 'myHep',
  ip_family: 2,
  time_sec: 1433719443,
  time_usec: 979,
  protocol: 17,
  proto_type: 1,
  srcIp: '192.168.100.1',
  dstIp: '192.168.1.23',
  srcPort: 5060,
  dstPort: 5060 
}
```

#### Example: Adding vendor extensions
```js
var HEPjs = require('./index');
HEPjs.addVendorExtensions({
    0x0008: {
        0x0080: {
            keyName: "conversationId"
        },
        0x0081: {
            keyName: "organizationId"
        },
        0x0082: {
            keyName: "siteId"
        },
        0x0083: {
            keyName: "trunkBaseId"
        },
        0x0084: {
            keyName: "edgeId"
        },
        0x0085: {
            keyName: "testUInt8",
            type: "UInt8"
        },
        0x0086: {
            keyName: "testUInt16",
            type: "UInt16"
        },
        0x0087: {
            keyName: "testUInt32",
            type: "UInt32"
        }
    }
});

var hepData = {
    "rcinfo": {
        "protocolFamily": 2,
        "protocol": 6,
        "srcIp": "172.26.26.72",
        "dstIp": "172.26.21.185",
        "srcPort": 64831,
        "dstPort": 8060,
        "timeSeconds": 1592975786,
        "timeUseconds": 669278,
        "payloadType": 1,
        "captureId": 8,
        "organizationId": "3bac7742-243f-4af7-ba39-f4098b941eda",
        "edgeId": "268c720e-b939-4484-966d-80a1123e3810",
        "conversationId": "",
        "siteId": "",
        "trunkBaseId": "",
        "testUInt8": 5,
        "testUInt16": 10,
        "testUInt32": 20
    },
    "payload": "INVITE sip:BellUser2@172.26.21.185:8060;transport=tls SIP/2.0\r\nTo:  <sip:BellUser2@172.26.21.185:8060>\r\nFrom:  <sip:BellStation1@172.26.21.185:8060>;tag=974329\r\ncall-id: 3935064a-294e-44d8-930d-1a87b90515bb\r\nCSeq: 1 INVITE\r\nallow-events: conference, talk, hold\r\nContact:  <sip:BellStation1@172.26.26.72:5061;transport=tls>\r\nx-phonesim-proxy-type: primary\r\ncontent-type: application/sdp\r\nx-edge-id: 268c720e-b939-4484-966d-80a1123e3810\r\nx-edge-name: qf-bell\r\nx-test-id: Station2Station\r\nx-test-name: Station to Station Keyword Test\r\nUser-Agent: PolycomSoundPointIP-SPIP_450-UA/4.0.10.0689_000025CC0001\r\nx-phonesim: 1.0.0-534\r\ncontent-length: 567\r\nVia: SIP/2.0/TLS qf-lempel:5060;branch=z9hG4bK416647af6e43448b8fc9c8b804713a0e\r\n\r\nv=0\r\no=- 4056025290 3801964586 IN IP4 172.26.26.72\r\ns= \r\nt=0 0\r\na=group:ANAT 1 2\r\nm=audio 20522 RTP/SAVP 0 8 9 101\r\nc=IN IP4 172.26.26.72\r\na=mid:1\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=crypto:1 AES_CM_256_HMAC_SHA1_80 inline:ba6DaKfQLSQQbYNMtL1ng2xCVbJuihEgzeajdEWIHT4qGpfrPwuTMDIasyhSOA\r\na=sendrecv\r\nm=audio 23824 RTP/SAVP 0 8 9 101\r\nc=IN IP6 2620:102:c000:f10:d::6050\r\na=mid:2\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=crypto:1 AES_CM_256_HMAC_SHA1_80 inline:ba6DaKfQLSQQbYNMtL1ng2xCVbJuihEgzeajdEWIHT4qGpfrPwuTMDIasyhSOA\r\na=sendrecv\r\n"
};

var hepBuf = HEPjs.encapsulate(hepData.payload, hepData.rcinfo);
console.log(JSON.stringify(HEPjs.decapsulate(hepBuf), undefined, 2));

// Output:

// {
//   "rcinfo": {
//     "protocolFamily": 2,
//     "protocol": 6,
//     "srcIp": "172.26.26.72",
//     "dstIp": "172.26.21.185",
//     "srcPort": 64831,
//     "dstPort": 8060,
//     "timeSeconds": 1592975786,
//     "timeUseconds": 669278,
//     "payloadType": 1,
//     "captureId": 8,
//     "hepNodeName": "8",
//     "conversationId": "",
//     "organizationId": "3bac7742-243f-4af7-ba39-f4098b941eda",
//     "siteId": "",
//     "trunkBaseId": "",
//     "edgeId": "268c720e-b939-4484-966d-80a1123e3810",
//     "testUInt8": 5,
//     "testUInt16": 10,
//     "testUInt32": 20
//   },
//   "payload": "INVITE sip:BellUser2@172.26.21.185:8060;transport=tls SIP/2.0\r\nTo:  <sip:BellUser2@172.26.21.185:8060>\r\nFrom:  <sip:BellStation1@172.26.21.185:8060>;tag=974329\r\ncall-id: 3935064a-294e-44d8-930d-1a87b90515bb\r\nCSeq: 1 INVITE\r\nallow-events: conference, talk, hold\r\nContact:  <sip:BellStation1@172.26.26.72:5061;transport=tls>\r\nx-phonesim-proxy-type: primary\r\ncontent-type: application/sdp\r\nx-edge-id: 268c720e-b939-4484-966d-80a1123e3810\r\nx-edge-name: qf-bell\r\nx-test-id: Station2Station\r\nx-test-name: Station to Station Keyword Test\r\nUser-Agent: PolycomSoundPointIP-SPIP_450-UA/4.0.10.0689_000025CC0001\r\nx-phonesim: 1.0.0-534\r\ncontent-length: 567\r\nVia: SIP/2.0/TLS qf-lempel:5060;branch=z9hG4bK416647af6e43448b8fc9c8b804713a0e\r\n\r\nv=0\r\no=- 4056025290 3801964586 IN IP4 172.26.26.72\r\ns= \r\nt=0 0\r\na=group:ANAT 1 2\r\nm=audio 20522 RTP/SAVP 0 8 9 101\r\nc=IN IP4 172.26.26.72\r\na=mid:1\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=crypto:1 AES_CM_256_HMAC_SHA1_80 inline:ba6DaKfQLSQQbYNMtL1ng2xCVbJuihEgzeajdEWIHT4qGpfrPwuTMDIasyhSOA\r\na=sendrecv\r\nm=audio 23824 RTP/SAVP 0 8 9 101\r\nc=IN IP6 2620:102:c000:f10:d::6050\r\na=mid:2\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=crypto:1 AES_CM_256_HMAC_SHA1_80 inline:ba6DaKfQLSQQbYNMtL1ng2xCVbJuihEgzeajdEWIHT4qGpfrPwuTMDIasyhSOA\r\na=sendrecv\r\n"
// }
```

#### HEP/EEP Specs:

http://hep.sipcapture.org/


###### This Project is sponsored by [QXIP BV](http://qxip.net)

