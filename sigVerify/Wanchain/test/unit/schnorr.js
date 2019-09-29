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

signature = Buffer.from('17b387353cd78a304c198d2fa84bf863793ad322ff8d519757f0e175fa6c15f5', 'hex')

groupKey = Buffer.from('04109d80da280fcc2afb674784246888b50f213830ee06c66b677de222a284993db002a88189c74953cc7ed63f00e409bdbeff5083719223711b444fda60cfec69', 'hex')
groupKeyX = groupKey.slice(1, 33)
groupKeyY = groupKey.slice(33)

randomPoint = Buffer.from('049bd37b6a6c106f38ef99e504a2b112c1366418b2a9780862028d1c13b60c62550aabd96220a86ed9bf79395bf5cf2a826bbb237897936d8d6663e19307250c1c', 'hex')
randomPointX = randomPoint.slice(1, 33)
randomPointY = randomPoint.slice(33)

message = Buffer.from('af9b94303b49a49229da4169a0262b0f29a7d12acccb3bdcb74387d37940e509', 'hex')

contract('Schnorr_Verifier', async ([owner]) => {
	it('should deploy the contracts', async () => {
		
		console.log(colors.green('[INFO] owner: ', owner))
	
		// deploy contract
    schnorrVerifierInstance = await SchnorrVerifier.new({from: owner});
		schnorrVerifierInstanceAddress = schnorrVerifierInstance.address;
		console.log(colors.green('[INFO] schnorrVerifierInstanceAddress: ', schnorrVerifierInstanceAddress));
		assert.equal(await schnorrVerifierInstance.flag(), false)
        
    try {
    	await schnorrVerifierInstance.verify("0x17b387353cd78a304c198d2fa84bf863793ad322ff8d519757f0e175fa6c15f5", "0x109d80da280fcc2afb674784246888b50f213830ee06c66b677de222a284993d", "0xb002a88189c74953cc7ed63f00e409bdbeff5083719223711b444fda60cfec69", "0x9bd37b6a6c106f38ef99e504a2b112c1366418b2a9780862028d1c13b60c6255", "0x0aabd96220a86ed9bf79395bf5cf2a826bbb237897936d8d6663e19307250c1c", "0xaf9b94303b49a49229da4169a0262b0f29a7d12acccb3bdcb74387d37940e509", {from: owner});
    } catch (e) {
      retError = e
      console.log('error: ', e)
    }

    // assert.equal(await schnorrVerifierInstance.flag(), true)
    
    // console.log('hash message: ', await schnorrVerifierInstance.m())
    // console.log('signature: ', await schnorrVerifierInstance.sig())
    console.log('flag: ', await schnorrVerifierInstance.flag())

	}) 
})
