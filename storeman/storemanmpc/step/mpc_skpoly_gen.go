package step

import (
	"crypto/rand"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/shcnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type RandomPolynomialGen struct {
	randCoefficient []big.Int          //coefficient
	message         map[uint64]big.Int //Polynomial result
	polyValue       []big.Int
	result          *big.Int
}

func createSkPolyGen(degree int, peerNum int) *RandomPolynomialGen {
	return &RandomPolynomialGen{make([]big.Int, degree+1), make(map[uint64]big.Int), make([]big.Int, peerNum), nil}
}

func (poly *RandomPolynomialGen) initialize(peers *[]mpcprotocol.PeerInfo,
	result mpcprotocol.MpcResultInterface) error {

	log.Info("RandomPolynomialGen::initialize ", "len of recieved message", len(poly.message))


	/*
	key := mpcprotocol.MPCRPolyCoff + strconv.Itoa(int(req.selfIndex))

	coff := make([]big.Int, 0)
	for _, polyCmCoffItem := range req.polyCoff{
		coff = append(coff, polyCmCoffItem)
	}
	result.SetValue(key, coff[:])
	*/

	degree := len(poly.randCoefficient) - 1

	s, err := rand.Int(rand.Reader, crypto.S256().Params().N)
	if err != nil {
		log.SyslogErr("RandomPolynomialGen::initialize", "rand.Int fail. err", err.Error())
		return err
	}
	cof := shcnorrmpc.RandPoly(degree, *s)
	copy(poly.randCoefficient, cof)

	for i := 0; i < len(poly.polyValue); i++ {
		poly.polyValue[i] = shcnorrmpc.EvaluatePoly(poly.randCoefficient,
			new(big.Int).SetUint64((*peers)[i].Seed),
			degree)
		log.Info("RandomPolynomialGen::initialize poly ",
			"poly peerId", (*peers)[i].PeerID.String(),
			"poly x seed", (*peers)[i].Seed)
	}

	return nil
}

func (poly *RandomPolynomialGen) calculateResult() error {
	poly.result = big.NewInt(0)
	log.Info("RandomPolynomialGen::calculateResult ", "len of recieved message", len(poly.message))
	for _, value := range poly.message {
		poly.result.Add(poly.result, &value)
		poly.result.Mod(poly.result, crypto.S256().Params().N)
	}

	return nil
}
