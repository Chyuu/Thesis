package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

var rng = random.New()

type Alice struct {
	ID   string
	time time.Duration
}

func main() {
	//establish connection
	connection, err := net.Dial("tcp", "192.168.137.3:8000")
	if err != nil {
		log.Fatal(err)
	}
	//---------------------------------WORK-FIATSHAMIR-------------------------------------
	start := time.Now()
	suite := suites.MustFind("Ed25519")

	//----------------------------------------------------
	//Read G from Bob
	buffer0 := make([]byte, 1024)
	mLen0, err := connection.Read(buffer0)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t1 := time.Now()
	elapsed1 := t1.Sub(start)
	fmt.Println("G", mLen0)
	var G_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer0[:mLen0]), &G_pt)

	//Read H from Bob
	buffer1 := make([]byte, 1024)
	mLen1, err := connection.Read(buffer1)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t2 := time.Now()
	elapsed2 := t2.Sub(start)
	fmt.Println("H", mLen1)
	var H_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer1[:mLen1]), &H_pt)

	////Read xG from Bob
	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t3 := time.Now()
	elapsed3 := t3.Sub(start)
	fmt.Println("xG", mLen)
	var xG_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer[:mLen]), &xG_pt)

	//Read xH from Bob
	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t4 := time.Now()
	elapsed4 := t4.Sub(start)
	fmt.Println("xH", mLen2)
	var xH_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer2[:mLen2]), &xH_pt)

	//Make Rand c and Send c to Bob
	c := suite.Scalar().Pick(rng)
	buf := bytes.Buffer{}
	suite.Write(&buf, &c)
	fmt.Println("c", len(buf.Bytes()))
	// Send c to Bob
	connection.Write(buf.Bytes())
	t5 := time.Now()
	elapsed5 := t5.Sub(start)

	//Read vG from Bob
	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t6 := time.Now()
	elapsed6 := t6.Sub(start)
	fmt.Println("vG", mLen3)
	var vG kyber.Point
	suite.Read(bytes.NewBuffer(buffer3[:mLen3]), &vG)

	//Read vH from Bob
	buffer4 := make([]byte, 1024)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t7 := time.Now()
	elapsed7 := t7.Sub(start)
	fmt.Println("vH", mLen4)
	var vH kyber.Point
	suite.Read(bytes.NewBuffer(buffer4[:mLen4]), &vH)

	//Read r form Bob
	buffer5 := make([]byte, 1024)
	mLen5, err := connection.Read(buffer5)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t8 := time.Now()
	elapsed8 := t8.Sub(start)

	fmt.Println("r", mLen5)
	var r kyber.Scalar
	if err := suite.Read(bytes.NewBuffer(buffer5[:mLen5]), &r); err != nil {
		log.Fatal("...")
	}

	//mul r and G
	rG := suite.Point().Mul(r, G_pt)
	//mul r and H
	rH := suite.Point().Mul(r, H_pt)

	//mul r and xG
	cxG := suite.Point().Mul(c, xG_pt)
	//mul r and xH
	cxH := suite.Point().Mul(c, xH_pt)

	//add rG and cXG
	a := suite.Point().Add(rG, cxG)
	//add rH and cXH
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G_pt, H_pt)

	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG_pt, xH_pt)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("\nAlice :\n a:\t%s\n b:\t%s\n\n", a, b)

	fmt.Printf("\nBob :\n a:\t%s\n b:\t%s\n\n", vG, vH)

	//Conditon for Verification a and b
	if !(vG.Equal(a) && vH.Equal(b)) {
		fmt.Println("Verifikasi Gagal!")
	} else {
		fmt.Println("Verifikasi Berhasil")
	}
	connection.Close()

	t9 := time.Now()
	elapsed9 := t9.Sub(start)
	fmt.Printf("\n\nOperation that takes %d milliseconds.\n", elapsed9.Milliseconds())

	records := []Alice{
		{"Reading 1", elapsed1},
		{"Reading 2", elapsed2},
		{"Reading 3", elapsed3},
		{"Reading 4", elapsed4},
		{"Sending 5", elapsed5},
		{"Reading 6", elapsed6},
		{"Reading 7", elapsed7},
		{"Reading 8", elapsed8},
		{"Operation that takes", elapsed9},
	}

	file, err := os.Create("FiatA.csv") // create file
	if err != nil {
		log.Fatal(err)
	}

	w := csv.NewWriter(file)

	for _, record := range records {
		row := []string{record.ID, strconv.FormatInt(record.time.Milliseconds(), 10)}
		if err := w.Write(row); err != nil {
			log.Fatalln("error writing record to file", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	file.Close()

}
