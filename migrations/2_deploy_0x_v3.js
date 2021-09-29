const ERC20Proxy = artifacts.require('ERC20Proxy');
const Exchange = artifacts.require('Exchange');

const CHAIN_ID = 4

module.exports = async (deployer, network, accounts) => {
    const txDefaults = { from: accounts[0], overwrite: true }

    await deployer.deploy(ERC20Proxy, txDefaults);
    const erc20Proxy = new ERC20Proxy.web3.eth.Contract(ERC20Proxy.abi, ERC20Proxy.address);

    await deployer.deploy(Exchange, CHAIN_ID, txDefaults);
    const exchange = new Exchange.web3.eth.Contract(Exchange.abi, Exchange.address);

    console.log('Configuring ERC20Proxy...');
    await erc20Proxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    console.log('ERC20Proxy configured!');


    console.log('Configuring Exchange...');
    await exchange.methods.registerAssetProxy(ERC20Proxy.address).send(txDefaults);
    console.log('Exchange configured!');


    const contractAddresses = {
        erc20Proxy: ERC20Proxy.address,
        exchange: Exchange.address
    };

    console.log("Addresses:", contractAddresses);
};
