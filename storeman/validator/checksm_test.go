package validator

import (
	"fmt"
	"testing"
)

func TestBuildKey(t *testing.T) {

	NewDatabase("smTest")

	grpId := "GrpId"
	smIndex := uint16(0)
	// empty
	isMc, err := IsMalice(grpId, smIndex)
	if err != nil {
		t.Fatalf("error %v", err.Error())
	}
	fmt.Printf("[should false] isMc %v\n", isMc)

	mc, err := maliceCount(grpId, smIndex)
	if err != nil {
		fmt.Print(err.Error())
	} else {
		fmt.Printf("mc %v\n", mc)
	}
	// set to 1
	err = SetMaliceCount(grpId, smIndex, uint8(1))
	if err != nil {
		t.Fatalf("error %v", err.Error())
	}

	isMc, err = IsMalice(grpId, smIndex)
	err = SetMaliceCount(grpId, smIndex, uint8(1))
	if err != nil {
		t.Fatalf("error %v", err.Error())
	}
	fmt.Printf("[should false]isMc %v\n", isMc)

	// set to 2
	err = SetMaliceCount(grpId, smIndex, uint8(2))
	if err != nil {
		t.Fatalf("error %v", err.Error())
	}

	isMc, err = IsMalice(grpId, smIndex)
	err = SetMaliceCount(grpId, smIndex, uint8(2))
	if err != nil {
		t.Fatalf("error %v", err.Error())
	}
	fmt.Printf("[should true]isMc %v\n", isMc)

}
