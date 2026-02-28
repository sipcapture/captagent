var should = require('chai').should(),
    hepnode = require('../index'),
    encode = hepnode.encode,
    decode = hepnode.decode;

describe('#escape', function() {
  it('HEP Encoder', function() {
    encode('HEP3').should.equal('HEP3').toString("binary");
  });

});

describe('#unescape', function() {
  it('HEP Decoder', function() {
    decode(('HEP3').toString("binary")).should.equal('HEP3');
  });

});
