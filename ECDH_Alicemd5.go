package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

var curve elliptic.Curve = elliptic.P256()

type Alice struct {
	ID   string
	time time.Duration
}

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
	//------------------------------Koneksi--------------------------------------------
	//establish connection
	start := time.Now()
	//---------------------------------WORK-ECDH-------------------------------------
	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	//-----------Lanjut-----------
	pub := priva.PublicKey

	buf := elliptic.Marshal(pub, pub.X, pub.Y)

	///send pub key
	_, err := connection.Write(buf)
	defer connection.Close()
	t1 := time.Now()
	elapsed1 := t1.Sub(start)
	time.Sleep(1 * time.Millisecond)
	fmt.Println("Byte send 1 (pub_buf) : ", binary.Size(buf))

	//perkalian kunci rahasia milik A dengan kunci publik
	ax, ay := curve.ScalarMult(pub.X, pub.Y, priva.D.Bytes())
	fmt.Println("Byte ax : ", binary.Size(ax.Bytes()))
	fmt.Println("Byte ay : ", binary.Size(ay.Bytes()))

	buf = elliptic.Marshal(curve, ax, ay)
	fmt.Println("Byte send 2 (aX dan aY (buf)) : ", binary.Size(buf))

	//kirim data ax dan ay kepada Bob
	_, err = connection.Write(buf)
	defer connection.Close()
	t2 := time.Now()
	elapsed2 := t2.Sub(start)
	time.Sleep(1 * time.Millisecond)

	//terima data dari Bob
	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t3 := time.Now()
	elapsed3 := t3.Sub(start)
	bB := buffer2[:mLen2]
	defer connection.Close()
	time.Sleep(1 * time.Millisecond)

	fmt.Println("Byte read 3 (bBx dan bBy (bB)) : ", binary.Size(bB))

	bBx, bBy := elliptic.Unmarshal(curve, bB)
	// Mekalikan kunci rahasia alice dengan kunci yang diterima dari bob
	ab, _ := curve.ScalarMult(bBx, bBy, priva.D.Bytes())

	//hash
	shared1 := md5.Sum(ab.Bytes())

	//--------------------------------HMAC-------------------------------------------
	length := 10
	data, err := GenerateRandomASCIIString(length)
	if err != nil {
		panic(err)
	}
	_, err = connection.Write([]byte(data))
	defer connection.Close()
	t7 := time.Now()
	elapsed7 := t7.Sub(start)
	time.Sleep(1 * time.Millisecond)
	fmt.Println("Byte data : ", binary.Size([]byte(data)))

	//mempersingkat atau down scale
	slice := shared1[:]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(md5.New, []byte(slice))

	// Write Data to it
	h.Write([]byte(data))
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	///terima data / read data
	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	t4 := time.Now()
	elapsed4 := t4.Sub(start)
	time.Sleep(1 * time.Millisecond)

	shaa := buffer3[:mLen3]
	sha2 := string(shaa[:])
	fmt.Println("Byte read 4 (shaa atau sha2) : ", binary.Size(shaa))

	///send data
	_, err = connection.Write([]byte(sha))
	defer connection.Close()
	t5 := time.Now()
	elapsed5 := t5.Sub(start)
	time.Sleep(1 * time.Millisecond)

	fmt.Println("Byte send 5 (sha) : ", binary.Size([]byte(sha)))
	//-------------------------------ALICE-------------------------------------------
	fmt.Printf("\nKunci Publik \t: (%x,%x)", pub.X, pub.Y)
	fmt.Printf("\nKunci Pribadi Alice\t: %x", priva.D)
	fmt.Printf("\nKunci Rahasia Alice\t: %x\n", ab)
	fmt.Printf("Hasil Hash Alice\t: %x", sha)
	fmt.Printf("\nHasil Hash Bob\t\t: %x", sha2)

	// fmt.Println("\nByte X : ", binary.Size(pub.X.Bytes()))
	// fmt.Println("Byte Y : ", binary.Size(pub.Y.Bytes()))
	// fmt.Println("Byte priva : ", binary.Size(priva.D.Bytes()))
	// fmt.Println("Byte sha : ", binary.Size([]byte(sha)))
	// fmt.Println("Byte sha2 : ", binary.Size([]byte(sha2)))
	//-------------------------Verifikasi-------------------------------------------------

	if !((sha) == (sha2)) {
		fmt.Printf("\n\nVerifikasi Gagal\n")
	} else {
		fmt.Printf("\n\nVerifikasi Berhasil\n")
	}
	connection.Close()
	t6 := time.Now()
	elapsed6 := t6.Sub(start)
	fmt.Printf("Operation that takes %d milliseconds.\n", elapsed6.Milliseconds())

	records := []Alice{
		{"Sending 1", elapsed1},
		{"Sending 2", elapsed2},
		{"Reading 3", elapsed3},
		{"Reading 4", elapsed4},
		{"Sending 5", elapsed5},
		{"Sending 6", elapsed7},
		{"Operation that takes", elapsed6},
	}

	file, err := os.Create("ecdhA.csv") // create file
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
