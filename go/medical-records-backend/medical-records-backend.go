package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cosminprunaru/chaincrypto"
	"github.com/gorilla/mux"
)

const (
	addRecordType    = 1
	searchRecordType = 2

	addTransaction     = 0
	getTransaction     = 1
	getAllTransactions = 2

	nodeAddress = "127.0.0.1:4400"
)

var doctorData = getDoctorMetadata()
var doctorPrivateKey = chaincrypto.ReadECDSAfromFile(keyPath + "/doctor/ecdsa-private.key")

/*
doctor -> private structure which
simulates electronic card
*/
type doctor struct {
	ID         int    `json:"id"`
	FirstName  string `json:"firstname"`
	LastName   string `json:"lastname"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	DoctorType string `json:"type"`
}

/*
pacient -> private structure which
simulates electronic card
*/
type pacient struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	CNP       string `json:"cnp"`
	Phone     string `json:"phone"`
}

type networkRequest struct {
	Type    int    `json:"optype"`
	Request string `json:"request"`
}

var keyPath = "/home/cosmin/javascript/medical_records_ui/assets/keys"

/*******************************************************
				RSA related functions
********************************************************/
func readKey(path string) rsa.PrivateKey {
	file, err := os.Open(path)
	var privKey rsa.PrivateKey

	if err != nil {
		fmt.Println("Key read error: ", err)
	}

	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&privKey)

	file.Close()

	return privKey
}

func readAESkey(path string) []byte {
	x, _ := ioutil.ReadFile(path)
	return x
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(rec Record, passphrase string) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(rec)

	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, buf.Bytes(), nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) Record {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	buf := bytes.NewBuffer(plaintext)
	var a Record
	dec := gob.NewDecoder(buf)
	dec.Decode(&a)

	return a
}

func getHash(p interface{}) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(p)

	h := sha1.New()

	h.Write(buf.Bytes())

	bs := h.Sum(nil)

	return bs
}

/*******************************************************
				RSA related functions
********************************************************/

/*******************************************************
				JSON related functions
********************************************************/
func getDoctorMetadata() doctor {
	raw, err := ioutil.ReadFile(keyPath + "/doctor/doctor.json")

	if err != nil {
		fmt.Println(err.Error())
	}

	var d doctor
	json.Unmarshal(raw, &d)
	return d
}

func getPacientMetadata() (pacient, error) {
	raw, err := ioutil.ReadFile(keyPath + "/pacient/pacient.json")

	if err != nil {
		fmt.Println(err.Error())
		return pacient{}, err
	}

	var p pacient
	json.Unmarshal(raw, &p)
	return p, nil
}

func (p pacient) toString() string {
	return toJSON(p)
}

func (d doctor) toString() string {
	return toJSON(d)
}

func toJSON(p interface{}) string {
	bytes, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err.Error())
	}

	return string(bytes)
}

/*******************************************************
			end of JSON related functions
********************************************************/

/*
Record -> data structure that describes a
medical record
*/
type Record struct {
	ID        int     `json:"id,omitempty"`
	Doctor    doctor  `json:"doctor,omitempty"`
	Pacient   pacient `json:"pacient,omitempty"`
	Payload   string  `json:"payload,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
}

type transaction struct {
	OperationType int
	PacientHash   []byte
	DoctorHash    []byte
	Data          []byte
	Signature     []byte
}

var records []Record
var transactions []transaction

/*
GetRecords -> function that gets all records
*/
func GetRecords(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(records)
}

/*
GetRecord -> function that gets a record by id
*/
func GetRecord(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	for _, item := range records {
		i, _ := strconv.Atoi(params["id"])
		if item.ID == i {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	json.NewEncoder(w).Encode(&Record{})
}

func getLastBlockID() int {
	p, _ := getPacientMetadata()
	pacientHash := getHash(p)
	dbLen := len(handleDBGetAllByHash(pacientHash))
	return dbLen
}

/*
CreateRecord -> function that creates a new record
*/
func CreateRecord(w http.ResponseWriter, r *http.Request) {
	var record Record
	var req networkRequest
	var err error

	log.Println("Received create record event")

	_ = json.NewDecoder(r.Body).Decode(&req)

	// check request type
	if req.Type != addRecordType {
		json.NewEncoder(w).Encode(Record{})
		return
	}

	record.Pacient, err = getPacientMetadata()

	if err != nil {
		json.NewEncoder(w).Encode(Record{})
		return
	}

	record.Payload = req.Request
	record.ID = getLastBlockID() + 1
	record.Timestamp = time.Now().Format(time.RFC850)
	record.Doctor = doctorData

	// read pacient key from card
	pacientAESKey := string(readAESkey(keyPath + "/pacient/aesKey.key"))

	// encrypt the pacient record
	cipher := encrypt(record, pacientAESKey)

	// sign the encrypted record
	signature, err := chaincrypto.SignMessage(doctorPrivateKey, cipher)

	// create new transaction
	var newTr transaction

	newTr.OperationType = addTransaction
	newTr.DoctorHash = getHash(doctorData)
	newTr.PacientHash = getHash(record.Pacient)
	newTr.Data = cipher
	newTr.Signature = signature

	log.Printf("Created new signed transaction: %x\n", newTr.Signature)

	go handleDBAdd(newTr)

	transactions = append(transactions, newTr)

	json.NewEncoder(w).Encode(record)
}

/*
SearchRecord -> function that searches all records by name
*/
func SearchRecord(w http.ResponseWriter, r *http.Request) {
	var foundRecords []Record
	var req networkRequest

	log.Println("Received search record event")

	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Type != searchRecordType {
		json.NewEncoder(w).Encode(Record{})
		return
	}
	p, _ := getPacientMetadata()

	pacientHash := getHash(p)

	// read pacient key from card
	pacientAESKey := string(readAESkey(keyPath + "/pacient/aesKey.key"))

	dbContent := handleDBGetAllByHash(pacientHash)

	log.Println(len(dbContent))

	for i := 0; i < len(dbContent); i++ {
		if chaincrypto.VerifyMessage(&doctorPrivateKey.PublicKey, dbContent[i].Data, dbContent[i].Signature) == true {
			log.Println("Transaction is valid")
		} else {
			log.Println("Transaction is compromised")
		}

		log.Printf("db hash: %x\n", dbContent[i].PacientHash)
		log.Printf("local hash: %x\n", pacientHash)

		if reflect.DeepEqual(dbContent[i].PacientHash, pacientHash) {
			// decrypt the record only if it is our pacients
			record := decrypt(dbContent[i].Data, pacientAESKey)

			if strings.Contains(strings.ToLower(record.Payload), strings.ToLower(req.Request)) {
				log.Println("Found record with matching criteria: ", req.Request)
				// add the record since we compared the hash of the pacient entire data
				foundRecords = append(foundRecords, record)
			}
		}
	}

	json.NewEncoder(w).Encode(foundRecords)
}

func handleDBAdd(t transaction) {
	conn, err := net.Dial("tcp", nodeAddress)

	// clean-up connection
	defer conn.Close()

	if err != nil {
		log.Println("Dial problem, aborting...")
		return
	}
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	enc := gob.NewEncoder(rw)
	err = enc.Encode(t)

	if err != nil {
		log.Println("Failed to encode gob", err)
		return
	}

	// send the transaction
	err = rw.Flush()
	if err != nil {
		log.Println("Flush failed.")
		return
	}

	log.Println("Sent transaction to DB")
}

func handleDBGetAllByHash(pacientHash []byte) []transaction {
	conn, err := net.Dial("tcp", nodeAddress)

	// clean-up connection
	defer conn.Close()

	if err != nil {
		log.Println("Dial problem, aborting...")
		return nil
	}
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	var empty transaction
	empty.OperationType = getAllTransactions

	enc := gob.NewEncoder(rw)
	err = enc.Encode(empty)

	if err != nil {
		log.Panicln("Failed to encode gob")
		return nil
	}

	// send the transaction
	err = rw.Flush()
	if err != nil {
		log.Println("Flush failed.")
		return nil
	}

	var rt []transaction

	dec := gob.NewDecoder(rw)
	err = dec.Decode(&rt)

	log.Println("Received transaction from DB")

	return rt
}

func main() {
	router := mux.NewRouter()

	log.Println("Starting server...")

	router.HandleFunc("/records", GetRecords).Methods("GET")
	router.HandleFunc("/records", CreateRecord).Methods("POST")
	router.HandleFunc("/records/{id}", GetRecord).Methods("GET")
	router.HandleFunc("/records/search", SearchRecord).Methods("POST")

	log.Fatal(http.ListenAndServe("localhost:8080", router))
}
