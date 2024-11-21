package block

type Visitor interface {
	StandardBlock(*StandardBlock) error
}
