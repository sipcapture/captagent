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
  var udpmessage = new Buffer(sipmessage);
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
      captagent.kill();
    })
    var sendHep = function(){
	out_socket.send(udpmessage, 0, udpmessage.length, 5060, iptarget, function(err) {
          if (err) console.log(err);
	});
    }

    in_socket.on('listening', function () {
	captagent.stdout.on('data', (data) => {
	     //if(!data.includes('ready')) return;	
	     setTimeout(sendHep, 1500);
    	})
    })
    in_socket.bind(9061, ipserver)
  })

  it('HEP should originate from 127.0.0.1', (done) => {
    assert.ok(network.address === '127.0.0.1');
    done();
  })
  it('should return HEP data', (done) => {
    assert.ok(decoded);
    done();
  })
  it('should return HEP payload', (done) => {
    assert.ok(decoded.payload.length > 0);
    done();
  })
 })

