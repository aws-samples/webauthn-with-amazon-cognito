[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/webcrypto-core/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/webcrypto-core.svg?branch=master)](https://travis-ci.org/PeculiarVentures/webcrypto-core)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/webcrypto-core/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/webcrypto-core?branch=master)

[![NPM](https://nodei.co/npm-dl/webcrypto-core.png?months=2&height=2)](https://nodei.co/npm/webcrypto-core/)

# webcrypto-core

We have created a number of WebCrypto polyfills including: [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl), [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11), and [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner).  `webcrypto-core` was designed to be a common layer to be used by all of these libraries for input validation.

Unless you intend to create a WebCrypto polyfill this library is probably not useful to you.

## Dependencies

Install all dependencies
```
npm install
```

> NOTE: `npm install` command downloads and installs modules to local folder. 
> You can install all dependencies globally 

typescript
```
npm install typescript --global
```

rollup
```
npm install rollup --global
```

mocha
```
npm install mocha --global
```

Single line command for all modules
```
npm install typescript rollup mocha --global
```

## Compilation 
Compile the source code using the following command:
```
npm run build
```
> NOTE: Command creates `webcrypto-core.js` and `webcrypto-core.min.js` files in `build` folder

Compile the source code with declaration using the next command:
```
tsc --declaration
```

## Test
```
npm test
```

## Size

| Files                   | Size       |
|-------------------------|------------|
| webcrypto-core.js       | 59Kb       |
| webcrypto-core.min.js   | 25Kb       |
