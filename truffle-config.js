const HDWalletProvider = require('@truffle/hdwallet-provider');

require('dotenv').config();

const mnemonic = process.env["MNEMONIC"];
const infuraKey = process.env["INFURA_KEY"];
const alchemyKey = process.env["ALCHEMY_KEY"];

module.exports = {
    /**
     * Networks define how you connect to your ethereum client and let you set the
     * defaults web3 uses to send transactions. If you don't specify one truffle
     * will spin up a development blockchain for you on port 9545 when you
     * run `develop` or `test`. You can ask a truffle command to use a specific
     * network from the command line, e.g
     *
     * $ truffle test --network <network-name>
     */

    networks: {
        // Useful for testing. The `development` name is special - truffle uses it by default
        // if it's defined here and no other network is specified at the command line.
        // You should run a client (like ganache-cli, geth or parity) in a separate terminal
        // tab if you use this network and you must also set the `host`, `port` and `network_id`
        // options below to some value.
        //
        development: {
            url: 'http://127.0.0.1:7545',
            network_id: '*'
        },
        development_local: {
            provider: function() {
              return new HDWalletProvider(
                process.env.MNEMONIC,
                `http://127.0.0.1:1317`
              )
            },
            network_id: 888,
            skipDryRun: true,
            gasPrice: 0,
            gas: 80000000
        },
        rinkeby: {
            network_id: 4,
            chain_id: 4,
            skipDryRun: true,
            provider: function() {
              return new HDWalletProvider(mnemonic, "https://rinkeby.infura.io/v3/"+ infuraKey, 1);
            }
        },
        rinkeby_alchemy: {
            network_id: 4,
            chain_id: 4,
            skipDryRun: true,
            provider: function() {
              return new HDWalletProvider(mnemonic, "https://eth-rinkeby.alchemyapi.io/v2/"+ alchemyKey, 1);
            }
        },
        kovan: {
            network_id: 42,
            chain_id: 42,
            provider: function() {
              return new HDWalletProvider(mnemonic, "https://kovan.infura.io/v3/"+ infuraKey, 1);
            }
        },
        injective: {
            provider: function() {
              return new HDWalletProvider(
                process.env.DEPLOYER_PRIVATE_KEY,
                `http://127.0.0.1:1317`
              )
            },
            network_id: 888,
            skipDryRun: true,
            gasPrice: 0,
            gas: 80000000
        },
    },

    // Set default mocha options here, use special reporters etc.
    mocha: {
        // timeout: 100000
    },

    compilers: {
        solc: {
            version: "0.6.12",
            settings: {
                optimizer: {
                    enabled: true,
                    runs: 20000
                },
                evmVersion: "istanbul"
            }
        }
    }
}
