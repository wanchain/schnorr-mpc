module.exports = {
  networks: {
  	development: {
  		host: '192.168.1.58',
  		port: 18545,
  		network_id: '*',
      gas: 4710000,
      gasPrice: 180e9
      // from: '0xcd5a7fcc744481d75ab3251545befb282e785882'
  	},
    rinkeby: {
      host: "18.236.235.133",
      port: 18545,
      network_id: "*", // Match any network id
      gas: 4700000,
      gasPrice: 40e9,
      from: "0x2d0e7c0813a51d3bd1d08246af2a8a7a57d8922e",
    },
    wantest: {
      host: "18.236.235.133",
      port: 8545,
      network_id: "*",
      gas: 4700000,
      gasPrice: 180e9,
      from: '0xb755dc08ee919f9d80ecac014ad0a7e1d0b3b231'
    }
  },
  // mocha: {
  //   reporter: 'eth-gas-reporter',
  //   // reporterOptions : {
  //   //   currency: 'USD',
  //   //   gasPrice: 180e9
  //   // }
  // }
}