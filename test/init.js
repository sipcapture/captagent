const assert = require('assert')
const spawn = require('child_process').spawn

/*
 * Start Captagent, Check Exit Code
 */
describe('CaptAgent Initialization', () => {
  let args = [
    "-v"
  ]
  let exitCode

  before((done) => {
    let process = spawn('../src/captagent', args)
    process.on('exit', (code) => {
      exitCode = code
      done()
    })
  })
  it('exit code should be zero', () => {
    assert.equal(exitCode, 0)
  })
 })

/*
 * Start Captagent, Check Exit Code
 */
describe('CaptAgent Version', () => {
  let args = [
    "-v"
  ]
  let exitCode
  let output

  before((done) => {
    let process = spawn('../src/captagent', args)
    process.stdout.on('data', function(data) {
      output = data.toString();
    });
    process.on('exit', (code) => {
      exitCode = code
      done()
    })
  })
  it('exit code should be zero', () => {
    assert.equal(exitCode, 0)
  })
  it('should print version number', () => {
    assert.ok(output.length > 0);
    assert.ok(output.startsWith('version'));
  })
 })
