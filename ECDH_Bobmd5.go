package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

type Bob struct {
	ID   string
	time time.Duration
}

var curve elliptic.Curve = elliptic.P256()

func main() {
	//------------------------------Koneksi--------------------------------------------
	//establish connection
	connection, err := net.Dial("tcp", "192.168.137.3:8000")
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()

	privb, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	//-----------Lanjut-----------
	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t1 := time.Now()
	elapsed1 := t1.Sub(start)
	pub := buffer[:mLen]
	time.Sleep(1 * time.Millisecond)

	x, y := elliptic.Unmarshal(curve, pub)

	bx, by := curve.ScalarMult(x, y, privb.D.Bytes())
	buf := elliptic.Marshal(curve, bx, by)

	//terima data
	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t2 := time.Now()
	elapsed2 := t2.Sub(start)
	aB := buffer2[:mLen2]
	time.Sleep(1 * time.Millisecond)

	//kirim data
	_, err = connection.Write(buf)
	defer connection.Close()
	t3 := time.Now()
	elapsed3 := t3.Sub(start)
	time.Sleep(1 * time.Millisecond)

	aBx, aBy := elliptic.Unmarshal(curve, aB)
	ba, _ := curve.ScalarMult(aBx, aBy, privb.D.Bytes())

	shared2 := md5.Sum(ba.Bytes())

	//--------------------------------HMAC-------------------------------------------
	buffer4 := make([]byte, 1024)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t7 := time.Now()
	elapsed7 := t7.Sub(start)
	time.Sleep(1 * time.Millisecond)

	dataa := buffer4[:mLen4]
	data := string(dataa[:])

	slice2 := shared2[:]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	g := hmac.New(md5.New, slice2)

	// Write Data to it
	g.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha2 := hex.EncodeToString(g.Sum(nil))

	///kirim data
	_, err = connection.Write([]byte(sha2))
	defer connection.Close()
	t4 := time.Now()
	elapsed4 := t4.Sub(start)
	time.Sleep(1 * time.Millisecond)

	///terima data
	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t5 := time.Now()
	elapsed5 := t5.Sub(start)

	shaa := buffer3[:mLen3]
	sha := string(shaa[:])

	defer connection.Close()
	time.Sleep(1 * time.Millisecond)

	//----------------------------------BOB-----------------------------------------------
	fmt.Printf("\nKunci Publik \t: (%x,%x)", x, y)
	fmt.Printf("\n\nKunci Pribadi Bob\t: %x", privb.D)
	fmt.Printf("\nKunci Rahasia Bob\t: %x", ba)
	fmt.Printf("\nHasil Hash (Alice)\t: %x", sha)
	fmt.Printf("\nHasil Hash (Bob)\t: %x", sha2)

	//-------------------------Verifikasi-------------------------------------------------

	if !((sha) == (sha2)) {
		fmt.Printf("\n\nVerifikasi Gagal\n")
	} else {
		fmt.Printf("\n\nVerifikasi Berhasil\n")
	}
	connection.Close()

	t6 := time.Now()
	elapsed6 := t6.Sub(start)
	fmt.Printf("\n\nOperation that takes %d milliseconds.\n", elapsed6.Milliseconds())

	records := []Bob{
		{"Reading 1", elapsed1},
		{"Reading 2", elapsed2},
		{"Sending 3", elapsed3},
		{"Sending 4", elapsed4},
		{"Reading 5", elapsed5},
		{"Reading 6", elapsed7},
		{"Operation that takes", elapsed6},
	}

	file, err := os.Create("ecdhB.csv") // create file
	if err != nil {
		log.Fatal(err)
	}

	w := csv.NewWriter(file)

	var data00 [][]string
	for _, record := range records {
		row := []string{record.ID, strconv.FormatInt(record.time.Milliseconds(), 10)}
		data00 = append(data00, row)
	}
	w.WriteAll(data00)
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	file.Close()
}
