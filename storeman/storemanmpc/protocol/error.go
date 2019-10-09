package protocol

import "errors"

var (
	ErrQuit               = errors.New("quit")
	ErrMpcResultExist     = errors.New("mpc Result is not exist")
	ErrContextType        = errors.New("err Context Type is error")
	ErrTimeOut            = errors.New("mpc Request is TimeOut")
	ErrPointZero          = errors.New("mpc Point is zero")
	ErrMpcSeedOutRange    = errors.New("mpc seeds are out range")
	ErrMpcSeedDuplicate   = errors.New("mpc seeds have duplicate")
	ErrTooLessStoreman    = errors.New("mpc alive Storeman is not enough")
	ErrFailedDataVerify   = errors.New("mpc signing data validate failed")
	ErrFailedAddApproving = errors.New("mpc add approving data failed")
	ErrMpcContextExist    = errors.New("mpc Context ID is already exist")
	ErrInvalidMPCAddr     = errors.New("invalid mpc account address")
	ErrInvalidMPCR        = errors.New("invalid signed data(R)")
	ErrInvalidMPCS        = errors.New("invalid signed data(S)")
	ErrVerifyFailed       = errors.New("verify failed")
)
