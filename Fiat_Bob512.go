package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

func read_int32(data []byte) int32 {
	return int32(uint32(data[0]) + uint32(data[1])<<8 + uint32(data[2])<<16 + uint32(data[3])<<24)
}

var rng = random.New()

//generate Random Ascii
func GenerateRandomASCIIString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			return result, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			result += string(n)
		}
	}
}

type Bob struct {
	ID   string
	time time.Duration
}

func main() {
	connection, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := connection.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		go serve(conn)
	}

}

func serve(connection net.Conn) {

	start := time.Now()
	//---------------------------------WORK-FIATSHAMIR-------------------------------------
	suite := suites.MustFind("Ed25519")
	length := 10 //kelipatan 100rb keatas waktunya dikali 2detik

	//generate ascii
	m, err := GenerateRandomASCIIString(length)
	if err != nil {
		panic(err)
	}

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = string(os.Args[1])
	}

	//Message go byte
	message := []byte(m)

	//hash
	scal := sha512.Sum512(message[:])

	x := suite.Scalar().SetBytes(scal[:32])

	//pick RNG point G and Send G to Alice
	G := suite.Point().Pick(rng)
	G_by, err := G.MarshalBinary()
	fmt.Println("G", len(G_by))
	_, err = connection.Write(G_by)

	t1 := time.Now()
	elapsed1 := t1.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//pick RNG point H and Send H to Alice
	H := suite.Point().Pick(rng)
	H_by, err := H.MarshalBinary()
	fmt.Println("H", len(H_by))
	_, err = connection.Write(H_by)
	t2 := time.Now()
	elapsed2 := t2.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//mul x ang G and Send xG to Alice
	xG := suite.Point().Mul(x, G)
	xG_by, err := xG.MarshalBinary()
	fmt.Println("xG", len(xG_by))
	_, err = connection.Write(xG_by)
	t3 := time.Now()
	elapsed3 := t3.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//mul x ang H and Send xH to Alice
	xH := suite.Point().Mul(x, H)
	xH_by, err := xH.MarshalBinary()
	fmt.Println("xH", len(xH_by))
	_, err = connection.Write(xH_by)
	t4 := time.Now()
	elapsed4 := t4.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//Read a Rand C from Alice
	var c kyber.Scalar
	buf := make([]byte, 1024)
	mLen, err := connection.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	if err := suite.Read(bytes.NewBuffer(buf[:mLen]), &c); err != nil {
		log.Fatal("...", err.Error())
	}
	t5 := time.Now()
	elapsed5 := t5.Sub(start)

	//pick rand V
	v := suite.Scalar().Pick(suite.RandomStream())
	//Mul v and G
	vG := suite.Point().Mul(v, G)
	//Send Vg to Alice
	vG_by, err := vG.MarshalBinary()
	fmt.Println("vG", len(vG_by))
	_, err = connection.Write(vG_by)
	t6 := time.Now()
	elapsed6 := t6.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//mul v and H
	vH := suite.Point().Mul(v, H)
	//Send Vh to Alice
	vH_by, err := vH.MarshalBinary()
	fmt.Println("vH", len(vH_by))
	_, err = connection.Write(vH_by)
	t7 := time.Now()
	elapsed7 := t7.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//mul (x and c) -> r , and then sub (v and r) -> r
	r := suite.Scalar()
	r.Mul(x, c).Sub(v, r)

	r_by, err := r.MarshalBinary()
	fmt.Println("r", len(r_by))
	//send r to Alice
	_, err = connection.Write(r_by)
	t8 := time.Now()
	elapsed8 := t8.Sub(start)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G, H)
	fmt.Printf("Bob's Password\t: %s\n", m)
	fmt.Printf("Bob's Secret (x): %s\n\n", x)
	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG, xH)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("Bob computes:\n v:\t%s\n r:\t%s\n\n", v, r)

	fmt.Println("Send 1 Byte G : ", binary.Size(G_by))
	fmt.Println("Send 2 Byte H : ", binary.Size(H))
	fmt.Println("Byte m : ", binary.Size(message))
	fmt.Println("Byte x : ", binary.Size(x))
	fmt.Println("Send 3 Byte xG : ", binary.Size(xG))
	fmt.Println("Send 4 Byte xH : ", binary.Size(xH_by))
	fmt.Println("read 5 Byte c: ", binary.Size(c))
	fmt.Println("Byte v : ", binary.Size(v))
	fmt.Println("Send 8  r : ", binary.Size(r))
	fmt.Println("Send 6 Byte vG : ", binary.Size(vG_by))
	fmt.Println("Send 7 Byte vH : ", binary.Size(vH))

	t9 := time.Now()
	elapsed9 := t9.Sub(start)
	fmt.Printf("Operation that takes %d milliseconds.\n", elapsed9.Milliseconds())

	records := []Bob{
		{"Sending 1", elapsed1},
		{"Sending 2", elapsed2},
		{"Sending 3", elapsed3},
		{"Sending 4", elapsed4},
		{"Reading 5", elapsed5},
		{"Sending 6", elapsed6},
		{"Sending 7", elapsed7},
		{"Sending 8", elapsed8},
		{"Operation that takes", elapsed9},
	}

	file, err := os.Create("FiatB.csv") // create file
	if err != nil {
		log.Fatal(err)
	}

	w := csv.NewWriter(file)

	var data [][]string
	for _, record := range records {
		row := []string{record.ID, strconv.FormatInt(record.time.Milliseconds(), 10)}
		data = append(data, row)
	}
	w.WriteAll(data)
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	file.Close()

}
