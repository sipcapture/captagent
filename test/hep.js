const assert = require('assert')
const spawn = require('child_process').spawn
const hepjs = require('hep-js')
const dgram = require('dgram')
const command = '../src/captagent'
const ipserver = '127.0.0.1'
const iptarget = '127.0.0.1'

/*
 * Start Captagent, Check Exit Code
 */
describe('CaptAgent HEP Basic', () => {
  let args = [
    "-n"
  ]

  let decoded
  let network
  var sipmessage = 'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP there.com:5060\r\nFrom: LittleGuy <sip:UserB@there.com>\r\nTo: LittleGuy <sip:UserB@there.com>\r\nCall-ID: 123456789@there.com\r\nCSeq: 2 REGISTER\r\n\r\n'
  var udpmessage = new Buffer.from(sipmessage);
  var in_socket = dgram.createSocket('udp4')
  var out_socket = dgram.createSocket('udp4')

  before((done) => {

    let captagent = spawn(command, args);
    captagent.on('exit', () => {
	in_socket.close();
	out_socket.close();
	done()
    })

    in_socket.on('message', (message,socket) => {
      decoded = hepjs.decapsulate(message);
      network = socket;
      // console.log(network,decoded);
      captagent.kill();
    })
    var sendHep = function(){
	out_socket.send(udpmessage, 0, udpmessage.length, 5060, iptarget, function(err) {
          if (err) console.log(err);
	});
    }

    in_socket.on('listening', function () {
	captagent.stdout.on('data', (data) => {
	     setTimeout(sendHep, 1200);
    	})
    })
    in_socket.bind(9061, ipserver)
  })

  it('UDP should originate from 127.0.0.1', (done) => {
    assert.ok(network.address === '127.0.0.1');
    done();
  })
  it('UDP should decode to HEP', (done) => {
    assert.ok(decoded);
    done();
  })
  it('HEP should contain rcinfo', (done) => {
    assert.ok(decoded.rcinfo);
    done();
  })
  it('HEP should contain payload', (done) => {
    assert.ok(decoded.payload.length > 0);
    done();
  })
  it('HEP payload should equal sent payload', (done) => {
    assert.ok(decoded.payload.length === udpmessage.length);
    done();
  })
  it('HEP capturePass should be "myhep"', (done) => {
    assert.ok(decoded.rcinfo.capturePass === 'myhep');
    done();
  })
  it('HEP dstPort should be 5060', (done) => {
    assert.ok(decoded.rcinfo.dstPort === 5060);
    done();
  })
  it('HEP srcPort should exist', (done) => {
    assert.ok(decoded.rcinfo.srcPort >= 0 );
    done();
  })
  it('HEP captureId should be 2001', (done) => {
    assert.ok(decoded.rcinfo.captureId === 2001);
    done();
  })
  it('HEP payloadType should be "myhep"', (done) => {
    assert.ok(decoded.rcinfo.payloadType === 1);
    done();
  })
  it('HEP srcIp should be "127.0.0.1"', (done) => {
    assert.ok(decoded.rcinfo.srcIp === '127.0.0.1');
    done();
  })
  it('HEP dstIp should be "127.0.0.1"', (done) => {
    assert.ok(decoded.rcinfo.dstIp === '127.0.0.1');
    done();
  })

 })


