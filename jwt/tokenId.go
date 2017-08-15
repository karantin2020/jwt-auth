package jwt

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

func TokenTime(id string) (time.Time, error) {
	tknId := TokenIdHex(id)
	return tknId.Time(), nil
}

type TokenId string

// objectIdCounter is atomically incremented when generating a new ObjectId
// using NewObjectId() function. It's used as a counter part of an id.
var tokenIdCounter uint32 = readRandomUint32()

// readRandomUint32 returns a random objectIdCounter.
func readRandomUint32() uint32 {
	var b [4]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(fmt.Errorf("cannot read random object id: %v", err))
	}
	return uint32((uint32(b[0]) << 0) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24))
}

// machineId stores machine id generated once and used in subsequent calls
// to NewObjectId function.
var machineId = readMachineId()
var processId = os.Getpid()

// readMachineId generates and returns a machine id.
// If this function fails to get the hostname it will cause a runtime error.
func readMachineId() []byte {
	var sum [3]byte
	id := sum[:]
	hostname, err1 := os.Hostname()
	if err1 != nil {
		_, err2 := io.ReadFull(rand.Reader, id)
		if err2 != nil {
			panic(fmt.Errorf("cannot get hostname: %v; %v", err1, err2))
		}
		return id
	}
	hw := md5.New()
	hw.Write([]byte(hostname))
	copy(id, hw.Sum(nil))
	return id
}

// NewObjectId returns a new unique ObjectId.
func NewTokenId() string {
	var b [12]byte
	// Timestamp, 4 bytes, big endian
	binary.BigEndian.PutUint32(b[:], uint32(time.Now().Unix()))
	// Machine, first 3 bytes of md5(hostname)
	b[4] = machineId[0]
	b[5] = machineId[1]
	b[6] = machineId[2]
	// Pid, 2 bytes, specs don't specify endianness, but we use big endian.
	b[7] = byte(processId >> 8)
	b[8] = byte(processId)
	// Increment, 3 bytes, big endian
	i := atomic.AddUint32(&tokenIdCounter, 1)
	b[9] = byte(i >> 16)
	b[10] = byte(i >> 8)
	b[11] = byte(i)
	return TokenId(b[:]).Hex()
}

// NewObjectIdWithTime returns a dummy ObjectId with the timestamp part filled
// with the provided number of seconds from epoch UTC, and all other parts
// filled with zeroes. It's not safe to insert a document with an id generated
// by this method, it is useful only for queries to find documents with ids
// generated before or after the specified timestamp.
func NewTokenIdWithTime(t time.Time) TokenId {
	var b [12]byte
	binary.BigEndian.PutUint32(b[:4], uint32(t.Unix()))
	return TokenId(string(b[:]))
}

// String returns a hex string representation of the id.
// Example: ObjectIdHex("4d88e15b60f486e428412dc9").
func (id TokenId) String() string {
	return string(id)
}

// Valid returns true if id is valid. A valid id must contain exactly 12 bytes.
func (id TokenId) Valid() bool {
	return len(id) == 12
}

// byteSlice returns byte slice of id from start to end.
// Calling this function with an invalid id will cause a runtime panic.
func (id TokenId) byteSlice(start, end int) []byte {
	if len(id) != 12 {
		panic("invalid ObjectId: " + string(id))
	}
	return []byte(string(id)[start:end])
}

// Time returns the timestamp part of the id.
// It's a runtime error to call this method with an invalid id.
func (id TokenId) Time() time.Time {
	// First 4 bytes of ObjectId is 32-bit big-endian seconds from epoch.
	secs := int64(binary.BigEndian.Uint32(id.byteSlice(0, 4)))
	return time.Unix(secs, 0)
}

// Hex returns a hex representation of the ObjectId.
func (id TokenId) Hex() string {
	return hex.EncodeToString([]byte(id))
}

// ObjectIdHex returns an ObjectId from the provided hex representation.
// Calling this function with an invalid hex representation will
// cause a runtime panic. See the IsObjectIdHex function.
func TokenIdHex(s string) TokenId {
	d, err := hex.DecodeString(s)
	if err != nil || len(d) != 12 {
		panic("invalid input to TokenIdHex: " + s)
	}
	return TokenId(d)
}
