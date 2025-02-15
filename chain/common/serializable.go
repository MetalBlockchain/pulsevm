package common

type Serializable interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}
