package unit

import (
	"bytes"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"math/rand"
	"regexp"
	"testing"
	"time"
)

// Scenario: A publish an Article, C downloads it with topology : A <-> B <-> C
func Test_Basic_Features_Download(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5))
	defer node2.Stop()

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5))
	defer node3.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())

	time.Sleep(2 * time.Second)

	title := "My article"
	content := " Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam varius maximus tellus, vel congue nunc" +
		" efficitur a. Duis vel sagittis lacus, a vulputate massa. Maecenas molestie tempor felis sit amet sodales. " +
		"Pellentesque porttitor convallis neque, iaculis maximus quam scelerisque blandit. Maecenas euismod nibh mi, " +
		"vel egestas mi vulputate ut. Mauris iaculis mattis est sed sodales. Mauris hendrerit malesuada lectus ut " +
		"dictum.\n\nDonec ornare lectus nec nunc maximus, at posuere ante posuere. Quisque finibus ex facilisis, " +
		"tristique elit eu, pulvinar ex. Curabitur accumsan at ex quis condimentum. Pellentesque mi nulla, tempor " +
		"posuere tellus fermentum, porta ullamcorper purus. Quisque id congue odio. Quisque imperdiet id velit nec " +
		"placerat. Nunc blandit, orci in volutpat congue, orci eros congue lectus, sit amet elementum ligula dui vitae " +
		"ligula. Proin tincidunt facilisis risus, non tempus ex semper eu. Vivamus ultrices magna et posuere finibus." +
		"\n\nNunc blandit, enim ullamcorper viverra scelerisque, quam magna volutpat justo, quis placerat augue magna " +
		"eget sapien. In dignissim magna nisi, vel fermentum turpis consequat eget. Aenean consequat pretium nulla non " +
		"blandit. Vestibulum sodales nibh vel sapien aliquet, vitae rhoncus metus suscipit. Nulla non mi accumsan, " +
		"tincidunt dui at, iaculis nisl. Aliquam convallis finibus ipsum. Quisque id massa vestibulum, congue velit eu," +
		" viverra orci. Vivamus metus metus, dictum non porta posuere, commodo sit amet arcu. "

	data := bytes.NewBuffer([]byte(content))

	articleID, err := node1.PublishArticle(title, data)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	require.NotEmpty(t, node3.GetSummary(articleID))
	res, err := node3.DownloadArticle("My article", node3.GetSummary(articleID).Metahash)
	require.NoError(t, err)

	require.Equal(t, []byte(content), res)

	require.Equal(t, 1, node1.GetStorage().GetNamingStore().Len())
	require.Equal(t, 1, node3.GetStorage().GetNamingStore().Len())
}

// Scenario test, with the following topology:
// ┌───────────┐
// ▼           │
// C ────► D   │
// │       │   │
// ▼       ▼   │
// A ◄───► B ──┘
func Test_Basic_Features_Scenario(t *testing.T) {
	rand.Seed(1)

	getFile := func(size uint) []byte {
		file := make([]byte, size)
		_, err := rand.Read(file)
		require.NoError(t, err)
		return file
	}

	getTest := func(transp transport.Transport) func(*testing.T) {
		return func(t *testing.T) {
			chunkSize := uint(1024)

			opts := []z.Option{
				z.WithChunkSize(chunkSize),
				// at least every peer will send a heartbeat message on start,
				// which will make everyone to have an entry in its routing
				// table to every one else, thanks to the antientropy.
				z.WithHeartbeat(time.Second * 200),
				z.WithAntiEntropy(time.Second * 5),
				z.WithAckTimeout(time.Second * 10),
			}

			nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeA.Stop()

			nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeB.Stop()

			nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeC.Stop()

			nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeD.Stop()

			nodeA.AddPeer(nodeB.GetAddr())
			nodeB.AddPeer(nodeA.GetAddr())
			nodeB.AddPeer(nodeC.GetAddr())
			nodeC.AddPeer(nodeA.GetAddr())
			nodeC.AddPeer(nodeD.GetAddr())
			nodeD.AddPeer(nodeB.GetAddr())

			// Wait for the anti-entropy to take effect, i.e. everyone gets the
			// heartbeat message from everyone else.
			time.Sleep(time.Second * 10)

			// > If I publish an article on NodeB I should be able to download it
			// from NodeB
			articleB1 := getFile(chunkSize*2 + 10)
			IDB1, err := nodeB.PublishArticle("articleB1", bytes.NewBuffer(articleB1))
			mhB1 := nodeB.GetSummary(IDB1).Metahash
			require.NoError(t, err)

			res1, err := nodeB.DownloadArticle("articleB1", mhB1)
			require.NoError(t, err)
			require.Equal(t, articleB1, res1)

			// > NodeA should be able to download article from B
			res, err := nodeA.DownloadArticle("articleB1", mhB1)
			require.NoError(t, err)
			require.Equal(t, articleB1, res)

			// > NodeA should have added "fileB" in its naming storage
			mh := nodeA.Resolve("articleB1")
			require.Equal(t, mhB1, mh)

			// Node B publish a new article
			articleB2 := getFile(chunkSize*3 + 15)
			IDB2, err := nodeB.PublishArticle("articleB2", bytes.NewBuffer(articleB2))
			mhB2 := nodeB.GetSummary(IDB2).Metahash
			require.NoError(t, err)

			// Node D publish an article
			articleD := getFile(chunkSize*4 + 15)
			IDD, err := nodeB.PublishArticle("articleD", bytes.NewBuffer(articleD))
			mhD := nodeB.GetSummary(IDD).Metahash
			require.NoError(t, err)

			time.Sleep(3 * time.Second)

			// > NodeA should be able to download articleB2 and articleD
			res, err = nodeA.DownloadArticle("articleB2", mhB2)
			require.NoError(t, err)
			require.Equal(t, articleB2, res)
			res, err = nodeA.DownloadArticle("articleD", mhD)
			require.NoError(t, err)
			require.Equal(t, articleD, res)

			// Let's add new nodes and see if they can index the articles and
			// download them

			// 	           ┌───────────┐
			//             ▼           │
			// F ──► E ──► C ────► D   │
			//             │       │   │
			// 	           ▼       ▼   │
			// 	           A ◄───► B ◄─┘

			nodeE := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeE.Stop()

			nodeF := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", opts...)
			defer nodeF.Stop()

			nodeE.AddPeer(nodeC.GetAddr())
			nodeF.AddPeer(nodeE.GetAddr())

			// wait for the anti-entropy to take effect, i.e. everyone get the
			// heartbeat messages sent by nodeE and nodeF.
			time.Sleep(time.Second * 10)

			// > NodeF should be able to index all files (2)

			names, err := nodeF.SearchAll(*regexp.MustCompile("article*"), 8, time.Second*4)
			require.NoError(t, err)
			require.Len(t, names, 3)
			require.Contains(t, names, "articleB1")
			require.Contains(t, names, "articleB2")
			require.Contains(t, names, "articleD")

			// > NodeE should be able to download articleB1, articleB2 and articleD
			res, err = nodeE.DownloadArticle("articleB1", mhB1)
			require.NoError(t, err)
			require.Equal(t, articleB1, res)
			res, err = nodeE.DownloadArticle("articleB2", mhB2)
			require.NoError(t, err)
			require.Equal(t, articleB2, res)
			res, err = nodeE.DownloadArticle("articleD", mhD)
			require.NoError(t, err)
			require.Equal(t, articleD, res)
		}
	}

	t.Run("channel transport", getTest(channelFac()))
	t.Run("UDP transport", getTest(udpFac()))
}
