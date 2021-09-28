const ERC20Proxy = artifacts.require('ERC20Proxy');
const ERC721Proxy = artifacts.require('ERC721Proxy');
const ERC20BridgeProxy = artifacts.require('ERC20BridgeProxy');
const ERC1155Proxy = artifacts.require('ERC1155Proxy');
const StaticCallProxy = artifacts.require('StaticCallProxy');
const MultiAssetProxy = artifacts.require('MultiAssetProxy');
const Exchange = artifacts.require('Exchange');
const DevUtils = artifacts.require('DevUtils');

const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'

const CHAIN_ID = 4

module.exports = async (deployer, network, accounts) => {
    const txDefaults = { from: accounts[0], overwrite: true }

    await deployer.deploy(ERC20Proxy, txDefaults);
    const erc20Proxy = new ERC20Proxy.web3.eth.Contract(ERC20Proxy.abi, ERC20Proxy.address);

    await deployer.deploy(ERC721Proxy, txDefaults);
    const erc721Proxy = new ERC721Proxy.web3.eth.Contract(ERC721Proxy.abi, ERC721Proxy.address);

    await deployer.deploy(ERC20BridgeProxy, txDefaults);
    const erc20BridgeProxy = new ERC20BridgeProxy.web3.eth.Contract(ERC20BridgeProxy.abi, ERC20BridgeProxy.address);

    await deployer.deploy(ERC1155Proxy, txDefaults);
    const erc1155Proxy = new ERC1155Proxy.web3.eth.Contract(ERC1155Proxy.abi, ERC1155Proxy.address);

    await deployer.deploy(StaticCallProxy, txDefaults);
    const staticCallProxy = new StaticCallProxy.web3.eth.Contract(StaticCallProxy.abi, StaticCallProxy.address);

    await deployer.deploy(MultiAssetProxy, txDefaults);
    const multiAssetProxy = new MultiAssetProxy.web3.eth.Contract(MultiAssetProxy.abi, MultiAssetProxy.address);

    await deployer.deploy(Exchange, CHAIN_ID, txDefaults);
    const exchange = new Exchange.web3.eth.Contract(Exchange.abi, Exchange.address);

    console.log('Configuring ERC20Proxy...');
    await erc20Proxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    await erc20Proxy.methods.addAuthorizedAddress(MultiAssetProxy.address).send(txDefaults);
    console.log('ERC20Proxy configured!');

    console.log('Configuring ERC721Proxy...');
    await erc721Proxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    await erc721Proxy.methods.addAuthorizedAddress(MultiAssetProxy.address).send(txDefaults);
    console.log('ERC721Proxy configured!');

    console.log('Configuring ERC1155Proxy...');
    await erc1155Proxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    await erc1155Proxy.methods.addAuthorizedAddress(MultiAssetProxy.address).send(txDefaults);
    console.log('ERC1155Proxy configured!');

    console.log('Configuring ERC20BridgeProxy...');
    await erc20BridgeProxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    await erc20BridgeProxy.methods.addAuthorizedAddress(MultiAssetProxy.address).send(txDefaults);
    console.log('ERC20BridgeProxy configured!');

    console.log('Configuring MultiAssetProxy...');
    await multiAssetProxy.methods.addAuthorizedAddress(Exchange.address).send(txDefaults);
    console.log('Configuring MultiAssetProxy...1');
    await multiAssetProxy.methods.registerAssetProxy(ERC20Proxy.address).send(txDefaults);
    console.log('Configuring MultiAssetProxy...2');
    await multiAssetProxy.methods.registerAssetProxy(ERC721Proxy.address).send(txDefaults);
    console.log('Configuring MultiAssetProxy...3');
    await multiAssetProxy.methods.registerAssetProxy(ERC1155Proxy.address).send(txDefaults);
    console.log('Configuring MultiAssetProxy...4');
    await multiAssetProxy.methods.registerAssetProxy(ERC20BridgeProxy.address).send(txDefaults);
    console.log('Configuring MultiAssetProxy...5');
    await multiAssetProxy.methods.registerAssetProxy(StaticCallProxy.address).send(txDefaults);
    console.log('MultiAssetProxy configured!');

    console.log('Configuring Exchange...');
    await exchange.methods.registerAssetProxy(ERC20Proxy.address).send(txDefaults);
    await exchange.methods.registerAssetProxy(ERC721Proxy.address).send(txDefaults);
    await exchange.methods.registerAssetProxy(ERC1155Proxy.address).send(txDefaults);
    await exchange.methods.registerAssetProxy(MultiAssetProxy.address).send(txDefaults);
    await exchange.methods.registerAssetProxy(StaticCallProxy.address).send(txDefaults);
    await exchange.methods.registerAssetProxy(ERC20BridgeProxy.address).send(txDefaults);
    console.log('Exchange configured!');


    const contractAddresses = {
        erc20Proxy: ERC20Proxy.address,
        erc721Proxy: ERC721Proxy.address,
        erc1155Proxy: ERC1155Proxy.address,
        exchange: Exchange.address,
        erc20BridgeProxy: ERC20BridgeProxy.address,
        forwarder: NULL_ADDRESS,
        multiAssetProxy: MultiAssetProxy.address,
        staticCallProxy: StaticCallProxy.address
    };

    console.log("Addresses:", contractAddresses);
};
