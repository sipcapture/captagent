const assert = require('assert');
const spawn = require('child_process').spawn;

/*
 * Start Captagent, Check Exit Code
 */
describe('CaptAgent Version', () => {
    let args = ["-v"];
    let exitCode;
    let output;

    before((done) => {
        let process = spawn('../src/captagent', args);
        process.stdout.on('data',
                          function(data) {
                              output = data.toString();
                          });
        process.on('exit', (code) => {
            exitCode = code;
            done();
        })
    })
    it('exit code should be zero', () => {
        assert.equal(exitCode, 0);
    })
    it('should print version number', () => {
        assert.ok(output.length > 0);
        assert.ok(output.startsWith('version'));
    })
})

/*
 * Start Captagent, Check list of devices and exit
 */
describe('CaptAgent -a option (List devices)', () => {
    let args = ["-a"];
    let exitCode;
    let output;

    before((done) => {
        let process = spawn('../src/captagent', args);
        process.stdout.on('data',
                          function(data) {                                                                                                        
                              output = data.toString();          
                          });                                                                                                   
        process.on('exit', (code) => {                                                                                                                    
            exitCode = code;
            done();                                                                                                                                
        })
    })
    it('exit code should be zero', () => {
        assert.equal(exitCode, 0);
    })
    it('should print the list of devices', () => {
        assert.ok(output.length > 0);
        assert.ok(output.startsWith('List'));
    })
})

/*
 * Start Captagent, Check configuration and exit 
 */
describe('CaptAgent -c option (Check configuration and exit)', () => {
    let args = ["-c"];
    let exitCode;
    let output;

    before((done) => {
        let process = spawn('../src/captagent', args);
        process.stdout.on('data',
                          function(data) {                                                                                                        
                              output = data.toString();                                                                                                                       
                          }
                         );                                                                                                              
        process.on('exit', (code) => {                                                                                                                    
            exitCode = code;                                                                                                      
            done();                                                                                                                                
        })
    })
    it('exit code should be zero', () => {
        assert.equal(exitCode, 0);
    })
    it('should load config file and exit', () => {
        assert.ok(output.length > 0);
        assert.ok(output.startsWith('[NOTICE]'));
    })
})
