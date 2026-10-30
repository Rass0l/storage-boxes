package crypto

type CryptoMetadata struct {
	CryptoVersion        int
	KDFAlgorithm         string
	KDFParamsJSON        string
	CipherAlgorithm      string
	CipherParamsJSON     string
	KeyWrappingAlgorithm string
}
