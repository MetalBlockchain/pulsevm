package name

import "strings"

var charmap = ".12345abcdefghijklmnopqrstuvwxyz"

type Name uint64

func (n Name) String() string {
	return nameToString(uint64(n))
}

func NewNameFromString(str string) Name {
	var n uint64
	for i := 0; i < len(str) && i < 12; i++ {
		n |= (charToSymbol(str[i]) & 0x1F) << uint(64-5*(i+1))
	}

	if len(str) > 12 {
		n |= charToSymbol(str[12]) & 0x0F
	}

	return Name(n)
}

func nameToString(value uint64) string {
	str := strings.Repeat(".", 13)

	tmp := value
	for i := uint32(0); i <= 12; i++ {
		var c byte
		if i == 0 {
			c = charmap[tmp&0x0F]
		} else {
			c = charmap[tmp&0x1F]
		}
		str = setCharAtIndex(str, 12-int(i), c)
		tmp >>= func() uint64 {
			if i == 0 {
				return 4
			}
			return 5
		}()
	}

	str = strings.TrimRight(str, ".")
	return str
}

func setCharAtIndex(s string, index int, c byte) string {
	if index < 0 || index >= len(s) {
		return s
	}
	chars := []byte(s)
	chars[index] = c
	return string(chars)
}

func charToSymbol(c byte) uint64 {
	if c >= 'a' && c <= 'z' {
		return uint64(c-'a') + 6
	}
	if c >= '1' && c <= '5' {
		return uint64(c-'1') + 1
	}
	return 0
}
