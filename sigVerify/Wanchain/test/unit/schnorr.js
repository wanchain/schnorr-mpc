const colors = require('colors/safe')
const SchnorrVerifier = artifacts.require('./SchnorrVerifier.sol')

let schnorrVerifierInstance,
    schnorrVerifierInstanceAddress,
    signature,
    groupKey,
    groupKeyX,
    groupKeyY,
    randomPoint,
    randomPointX,
    randomPointY,
    message,
    retError

signature = Buffer.from('c0e7fc619cb10827948c0965b5f07fb7c66cbecba6ecbc67291fac09ec0f1e7a', 'hex')

groupKey = Buffer.from('047a5380730dde59cc2bffb432293d22364beb250912e0e73b11b655bf51fd7a8adabdffea4047d7ff2a9ec877815e12116a47236276d54b5679b13792719eebb9', 'hex')
groupKeyX = groupKey.slice(1, 33)
// console.log('groupKeyX: ', groupKeyX)
groupKeyY = groupKey.slice(33)
// console.log('groupKeyY: ', groupKeyY)

randomPoint = Buffer.from('044ba1ba8e5e297c3267069407d54e7dd0405cbeb9511b9d2802e407253a360eb3d61ab9c56c3e3ddbbea97e9b194340c36259e6314d72290d53598b81cb75c5bb', 'hex')
randomPointX = randomPoint.slice(1, 33)
// console.log('randomPointX: ', randomPointX)
randomPointY = randomPoint.slice(33)
// console.log('randomPointY: ', randomPointY)

message = Buffer.from('f76ae2f74b52984faa585c27e55e72cb0b318d71621b448c52012923ad117230', 'hex')

contract('Schnorr_Verifier', async ([owner]) => {
	it('should deploy the contracts', async () => {
		
		console.log(colors.green('[INFO] owner: ', owner))
	
		// deploy contract
    schnorrVerifierInstance = await SchnorrVerifier.new({from: owner});
		schnorrVerifierInstanceAddress = schnorrVerifierInstance.address;
		console.log(colors.green('[INFO] schnorrVerifierInstanceAddress: ', schnorrVerifierInstanceAddress));
		assert.equal(await schnorrVerifierInstance.flag(), false)
        
    try {
    	await schnorrVerifierInstance.verify("0xc0e7fc619cb10827948c0965b5f07fb7c66cbecba6ecbc67291fac09ec0f1e7a", "0x7a5380730dde59cc2bffb432293d22364beb250912e0e73b11b655bf51fd7a8a", "0xdabdffea4047d7ff2a9ec877815e12116a47236276d54b5679b13792719eebb9", "0x4ba1ba8e5e297c3267069407d54e7dd0405cbeb9511b9d2802e407253a360eb3", "0xd61ab9c56c3e3ddbbea97e9b194340c36259e6314d72290d53598b81cb75c5bb", "0xf76ae2f74b52984faa585c27e55e72cb0b318d71621b448c52012923ad117230", {from: owner});
    } catch (e) {
      retError = e
      console.log('error: ', e)
    }

    assert.equal(await schnorrVerifierInstance.flag(), true)
    
    // console.log('hash message: ', await schnorrVerifierInstance.m())
    // console.log('signature: ', await schnorrVerifierInstance.sig())
    // console.log('flag: ', await schnorrVerifierInstance.flag())
    // console.log('hash: ', (await schnorrVerifierInstance.m()).toString())
	}) 
})
