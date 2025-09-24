package reconstruct

import (
	"context"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/nsuiteio/trial-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/trial-mpc-key-export/utility/strutil"
	"github.com/stretchr/testify/assert"
)

func TestReconstructEdDSA(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		threshold   int
		localShares []string
		expected    string
	}{
		{
			threshold: 1,
			localShares: []string{
				"0x1f8b08000000000000ffacd3b18a9e470fc5f17b79eaa7908e74a473deeefbbc29429a801b83d922c14be234860d4e63f6dec3e0de55ba69067efa8fe6dbf5e1f3f5a8e94cf7accb5184b4b5c1240536261d9df4188b4d59c8cdc9d9809cebe98a4569bae6bedefff9dbebcbcf4fd7639d0aac27869d002739ec5ac5c252570614729a139151cbce89a830dd5614a39139dab9af5ffebe1e1fb7ac09b1270662c31940a2d1c0e6ceb18549959d6125e835b623a2065c74bbc318f6fd9f0a9fefebff9ffff8f0d7f5f8f8ed7af7f5f59f97eb71bd7c0299beeeebdd972faf9fce08752455a935433183cc2345132c55b536229d9de08ca6d735b9d416433e7a5564aaccbb1705c99e4072494e97195871bc19eb58ef9a6bc95bf0006a9e630bcc0846f018eaf9edfe211dcd026a86eacc6231217bc134ce5ce860f41626151b84b3b862cec87d1e402df484326e447fc749a7a2b70e0b940821ba9c29f2dcd9540a905a0e4c14c4c9c8d3cc055bcf6fcff7f5d3d3d3fbfffdfaf5f7ebf1c3313a136cbbb326330bdc647812dbd579fa35cb45eca93e5cdaaeda6e64d7d9baa190b11dbc8b6b337b2c8d15014fa3e5959b357b96b531aa6ea91059fcde4c0925558ad1f95a8d7d7e7bfb170000ffff010000ffff378b30ac94030000",
				"0x1f8b08000000000000ffac93b18a5d471044ffe5c62fe8aaeeeaae7e99ad75609c189408c40b6cb4d8722258232762ffdd0cca375276933b9c73a6e6dbf5e1f3756f6019e4347781eedc510c375d2126dc88ca717226c640474e77e6a69c9e8c15320abc5deffffee3e5f9d7a7eb3eb9eeb0aaa36915174182c52207d326265672ee22d6a076965311914d0dabb662d9aadbf5dbbfd7fde38f3d73160ece76b40aa41a6a1dd1236f5722e8f062d511881c153ae2f86ead231545a03dfdb85d3f7ffeebc33fd7fde3b7ebddd797ff9eaffbf5fc8912f6ba5defbe7c79f97414f29064c2b30a47378143ca1295ce2c4f041605aadb5db3d9187952e13df4ce009cab5b0d93f66e07a191d495abe058bd83988dd999d5acbd93dc265d3a9f650a118ad061c8c7ebed4d749692cc6eb980540af4ee50581e2f56286a920dc784b8488d856e6f9d0b7099d561c48d51dfe1ec5371270f16658b66542e60e9fc33304cdae50d7624ad46e034dbe4ae1faf8fdbf5cbd3d3fb9f7efffae7757f53a300aa760bd900921a28b6c1a92c9c7ea5336dcea9de1aed6ee654119567752d133115baa56657a85ebbd711dc2e9677bca5ec39632db6b3ca4e0652df9b1934cefb893687539cc7ebebff000000ffff010000ffffcb438b9793030000",
			},
			expected: "0x01cabefc8055e12e9337c8a57dd3967d45e61a84020aa58d7c209f035873f667",
		},
		// TODO: add more test cases
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			shares := make([]*keygen.LocalPartySaveData, len(tc.localShares))
			for i, shareHex := range tc.localShares {
				shareBs, err := strutil.FromHex(shareHex)
				if err != nil {
					t.Fatal(err)
				}
				share, err := keyutil.LocalDataFromBytesEdDSA(ctx, shareBs)
				if err != nil {
					t.Fatal(err)
				}
				shares[i] = share
			}
			prvKey, err := ReconstructEdDSA(ctx, tc.threshold, shares)
			if err != nil {
				t.Fatal(err)
			}
			prvStr := strutil.ToHex(prvKey.Serialize())
			assert.Equal(t, tc.expected, prvStr)
		})
	}
}
