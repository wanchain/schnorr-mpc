package osmconf

import (
	"fmt"
	"testing"
)

func TestGetOsmConf(t *testing.T) {
	osf := GetOsmConf()
	if osf != nil {
		fmt.Printf("error osf shoud be nil")
	}
}

func TestNewOsmConf(t *testing.T) {
	_, err := NewOsmConf()
	if err != nil {
		t.Errorf("error:%v",err.Error())
	}
}

func TestLoadCnf(t *testing.T) {
	NewOsmConf()
	GetOsmConf().LoadCnf("/home/jacob/storeman.json")
}


func TestIntersect(t *testing.T) {
	s1 := []uint16{1,2,3,4}
	s2 := []uint16{2,3,4,5,6,7}

	s := Intersect(s1,s2)
	fmt.Printf("%v",s)
}

func TestDifference(t *testing.T) {
	s1 := []uint16{1,2,3,4}
	s2 := []uint16{2,3,4,5,6,7}

	s := Difference(s1,s2)
	fmt.Printf("%v\n",s)

	s = Difference(s2,s1)
	fmt.Printf("%v\n",s)

	s = Difference(s1,s1)
	fmt.Printf("%v\n",s)
}