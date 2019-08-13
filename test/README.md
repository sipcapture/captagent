## CaptAgent CI

Automated tests for Captagent using Node JS and Mocha.

NOTICE: `sudo` rights are required to spawn the agent and test sockets on interface `any`

![ezgif com-optimize 44](https://user-images.githubusercontent.com/1423657/36928259-bf097698-1e84-11e8-85ee-d3ba9dd97e4d.gif)

### Usage
```
npm install -g mocha
npm install hep-js
sudo npm test
```

#### Units
##### Initialization
This suite will initialized the compiled agent and check it returns a version number.
```
sudo mocha init.js
```
##### HEP Functionality
This suite will test SIP and HEP features using the compiled agent, feeding it SIP and expecting HEP back.
```
sudo mocha hep.js
```
