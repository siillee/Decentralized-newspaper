package impl

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"io"
	"math"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const bufSize = 65000

func (n *node) Upload(data io.Reader) (string, error) {
	blobStore := n.conf.Storage.GetDataBlobStore()

	buf := make([]byte, bufSize)
	nRead, err := data.Read(buf)
	if err != nil {
		return "", err
	}
	buf = buf[:nRead]

	nChunks := int(math.Ceil(float64(nRead) / float64(n.conf.ChunkSize)))
	chunks := make([][]byte, nChunks)
	chunkHashes := make([]string, nChunks)

	for i := 0; i < nChunks; i++ {
		start := int(n.conf.ChunkSize) * i
		end := start + int(n.conf.ChunkSize)
		if end > nRead {
			end = start + (nRead % int(n.conf.ChunkSize)) // last chunk
		}

		chunks[i] = buf[start:end]
		chunkHashes[i] = sha256Encode(chunks[i])

		blobStore.Set(chunkHashes[i], chunks[i])
	}

	metaHashBuf := make([]byte, nChunks*32)
	for i := 0; i < nChunks; i++ {
		sha := sha256(chunks[i])
		for j := 0; j < 32; j++ {
			metaHashBuf[i*32+j] = sha[j]
		}
	}
	metaHash := sha256Encode(metaHashBuf)
	metaFile := []byte(strings.Join(chunkHashes, peer.MetafileSep))
	blobStore.Set(metaHash, metaFile)
	return metaHash, nil
}
func sha256(x []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(x)
	return h.Sum(nil)
}

func sha256Encode(x []byte) string {
	return hex.EncodeToString(sha256(x))
}

func (n *node) GetCatalog() peer.Catalog {
	return n.catalog
}

func (n *node) UpdateCatalog(key, peer string) {
	n.catalog.Update(key, peer)
}

func (n *node) Download(metahash string) ([]byte, error) {
	blobStore := n.conf.Storage.GetDataBlobStore()
	metafile := blobStore.Get(metahash)
	if len(metafile) == 0 {
		dest, err := n.catalog.GetRandomPeer(metahash)
		if err != nil {
			return nil, xerrors.Errorf("[%s] unable to get the metafile", n.GetAddress())
		}

		metafile, err = n.requestManager.SendDataRequest(dest, metahash)
		if err != nil {
			return nil, xerrors.Errorf("[%s] error while sending data request for metafile : %v", n.GetAddress(), err)
		}

		blobStore.Set(metahash, metafile)
	}

	chunkHashes := strings.Split(string(metafile), peer.MetafileSep)
	buffer := bytes.Buffer{}

	for _, chunkHash := range chunkHashes {
		chunk := blobStore.Get(chunkHash)
		if len(chunk) == 0 {
			dest, err := n.catalog.GetRandomPeer(chunkHash)
			if err != nil {
				return nil, xerrors.Errorf("[%s] unable to get the chunkHash", n.GetAddress())
			}

			chunk, err = n.requestManager.SendDataRequest(dest, chunkHash)
			if err != nil {
				return nil, xerrors.Errorf("[%s] error while sending data request for chunkHash : %v", n.GetAddress(), err)
			}
			blobStore.Set(chunkHash, chunk)
		}
		buffer.Write(chunk)
	}

	return buffer.Bytes(), nil

}

func (n *node) Tag(name string, mh string) error {
	namingStore := n.conf.Storage.GetNamingStore()
	namingStore.Set(name, []byte(mh))
	return nil
}

func (n *node) Resolve(name string) string {
	namingStore := n.conf.Storage.GetNamingStore()
	return string(namingStore.Get(name))
}

func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) ([]string, error) {
	matches := n.searchFilesLocally(reg.String())

	neighbors := n.GetNeighbors("")
	if len(neighbors) > 0 {
		budgets := DivideBudget(budget, neighbors)
		responses := n.requestManager.SendSearchRequest(n.GetAddress(), reg.String(), neighbors, budgets, timeout)

		for _, fileInfo := range responses {
			matches[fileInfo.Name] = fileInfo.Metahash
		}
	}

	filenames := make([]string, 0, len(matches))
	for k := range matches {
		filenames = append(filenames, k)
	}

	return filenames, nil
}

func (n *node) SearchFirst(reg regexp.Regexp, conf peer.ExpandingRing) (string, error) {
	matches := n.searchFilesLocally(reg.String())
	for filename, metaHash := range matches {
		if n.hasAllChunks(metaHash) {
			return filename, nil
		}
	}

	neighbors := n.GetNeighbors("")
	if len(neighbors) == 0 {
		return "", nil
	}

	budget := conf.Initial
	for i := 0; i < int(conf.Retry); i++ {
		budgets := DivideBudget(budget, neighbors)
		responses := n.requestManager.SendSearchRequest(n.GetAddress(), reg.String(), neighbors, budgets, conf.Timeout)
		for j := 0; j < len(responses); j++ {
			isFullFile := true
			for _, chunk := range responses[j].Chunks {
				if len(chunk) == 0 {
					isFullFile = false
					break
				}
			}
			if isFullFile {
				return responses[j].Name, nil
			}
		}

		budget *= conf.Factor
	}

	return "", nil
}

func DivideBudget(budget uint, neighbors []string) []int {
	splitBudget := make([]int, len(neighbors))
	for i := 0; i < len(neighbors); i++ {
		splitBudget[i] = int(budget) / len(neighbors) // default value
	}
	for i := 0; i < int(budget)%len(neighbors); i++ {
		splitBudget[i]++ // add remaining budget
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(splitBudget), func(i, j int) { splitBudget[i], splitBudget[j] = splitBudget[j], splitBudget[i] })
	return splitBudget
}

func (n *node) searchFilesLocally(pattern string) map[string]string {
	namingStore := n.conf.Storage.GetNamingStore()
	matches := make(map[string]string)
	lookForMatch := func(key string, val []byte) bool {
		match, _ := regexp.MatchString(pattern, key)
		if match {
			matches[key] = string(val)
		}
		return true
	}
	namingStore.ForEach(lookForMatch)
	return matches
}

func (n *node) constructFileInfo(name, hash string) (types.FileInfo, bool) {
	blobStore := n.conf.Storage.GetDataBlobStore()

	metafile := blobStore.Get(hash)
	if len(metafile) == 0 {
		return types.FileInfo{}, false
	}

	chunkHashes := strings.Split(string(metafile), peer.MetafileSep)
	chunks := make([][]byte, len(chunkHashes))

	for j, chunkHash := range chunkHashes {
		if len(blobStore.Get(chunkHash)) > 0 {
			chunks[j] = []byte(chunkHash)
		}
	}

	fileInfo := types.FileInfo{
		Name:     name,
		Metahash: hash,
		Chunks:   chunks,
	}
	return fileInfo, true
}

func (n *node) hasAllChunks(metaHash string) bool {
	blobStore := n.conf.Storage.GetDataBlobStore()
	metafile := blobStore.Get(metaHash)
	if len(metafile) == 0 {
		return false
	}
	chunkHashes := strings.Split(string(metafile), peer.MetafileSep)
	for _, chunkHash := range chunkHashes {
		if len(blobStore.Get(chunkHash)) == 0 {
			return false
		}
	}
	return true
}
