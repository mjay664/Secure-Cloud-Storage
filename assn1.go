package assn1

//@author MJay Dheeraj(c) 2019
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)

}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func encodemacanddata(data []byte, hmac []byte) (encoded []byte, err error) {
	var en = [][]byte{data, hmac}

	encoded, err = json.Marshal(en)
	return
}

func decodemacanddata(encoded []byte) (data []byte, mac []byte, err error) {
	var de [][]byte

	err = json.Unmarshal(encoded, &de)
	if err != nil {
		return nil, nil, err
	}
	data = de[0]
	mac = de[1]
	return data, mac, nil
}

func compare(data1 []byte, data2 []byte) (equal bool) {
	equal = false
	rc := userlib.NewHMAC(data1)
	rc.Write(data1)
	ss := rc.Sum(nil)

	if userlib.Equal(ss, data2) {
		equal = true
	}

	return equal
}

func generatekey(key []byte, value string) (datakey string) {
	x := []byte(value)
	userlib.CFBEncrypter(key, []byte("6295141.34537865")).XORKeyStream(x, x)
	datakey = string(x)
	return datakey
}

func storeiterater(data []byte, inode [][]byte, xref []byte, iv []byte, offset int, u string, filename string) (in [][]byte, err error) {

	var x = make([]byte, 16)
	copy(x, xref)

	r := (len(data) / configBlockSize)
	//fmt.Println((len(data) / configBlockSize))
	for i := 0; i < r; i++ {

		temp := data[:configBlockSize]
		data = data[configBlockSize:]

		var tempkey = make([]byte, 16)
		copy(tempkey, x)
		var tempiv = make([]byte, 16)
		copy(tempiv, iv)

		tempkey[0] = tempkey[0] ^ byte(offset)
		iname := generatekey(tempkey, (u + filename + string(offset)))

		var letmebetemp = make([]byte, configBlockSize)
		copy(letmebetemp, temp)

		rc := userlib.NewHMAC(append(letmebetemp, []byte(iname)...))
		_, err := rc.Write(append(letmebetemp, []byte(iname)...))
		hmac := rc.Sum(nil)
		if err != nil {
			return nil, err
		}

		temp, err = encodemacanddata(temp, hmac)

		tempiv[0] = tempiv[0] ^ byte(offset)

		userlib.CFBEncrypter(tempkey, tempiv).XORKeyStream(temp, temp)

		userlib.DatastoreSet(iname, temp)

		inode = append(inode, []byte(iname))
		//		fmt.Println([]byte(iname))
		offset++
	}
	in = inode

	return in, err
}

func loadstorefilerecord(key []byte, iv []byte, datakey string, store bool, record fileRecord) (filerecord fileRecord, err error) {

	err = errors.New("HMAC comparision failed , found different HMACs")

	if store {
		fileracordbytes, err := json.Marshal(record)

		xcc := userlib.NewHMAC(fileracordbytes)
		_, err = xcc.Write(fileracordbytes)
		filerecardhmac := xcc.Sum(nil)

		fileracordbytes, err = encodemacanddata(fileracordbytes, filerecardhmac)
		filekey := generatekey(key, datakey)
		userlib.CFBEncrypter(key, iv).XORKeyStream(fileracordbytes, fileracordbytes)
		userlib.DatastoreSet(filekey, fileracordbytes)

		return filerecord, err
	}
	filekey := generatekey(key, datakey)
	fileracordbytes, flag := userlib.DatastoreGet(filekey)
	if flag == false {
		return filerecord, errors.New("Somethig Wrong")
	}
	userlib.CFBDecrypter(key, iv).XORKeyStream(fileracordbytes, fileracordbytes)
	fileracordbytes, mac, err := decodemacanddata(fileracordbytes)
	if compare(fileracordbytes, mac) == false || err != nil {
		return filerecord, err
	}
	err = json.Unmarshal(fileracordbytes, &record)
	filerecord = record
	return filerecord, err
}

//User : User structure used to store the user information
type User struct {
	Username   string
	Privatekey *userlib.PrivateKey
	Argon2key  []byte
	IV         []byte
	Filecount  int
	Filerecord []string
}

type fileRecord struct {
	Fileowner     string
	IV            []byte
	Sharingflag   bool
	Inodelocation []byte
	Sharedkey     []byte
}

type sharingRecord struct {

}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	if len(data)%configBlockSize != 0 || userdata == nil {
		return errors.New("Error Block Size")
	}
	var inode [][]byte

	var x = make([]byte, 16)
	copy(x, userdata.Argon2key)

	inodekey := generatekey(x, (userdata.Username + filename + "inode"))

	//creating filerecord
	var filerecord fileRecord
	filerecord.Fileowner = userdata.Username
	filerecord.Sharingflag = false
	filerecord.Inodelocation = []byte(inodekey)
	filerecord.IV = userlib.Argon2Key(userlib.RandomBytes(64), []byte(userdata.Username+filename), 16)
	_, err = loadstorefilerecord(x, userdata.IV, userdata.Username+filename, true, filerecord)

	userdata.Filerecord = append(userdata.Filerecord, filename)
	userdata.Filecount++

	inode, err = storeiterater(data, inode, x, filerecord.IV, 0, userdata.Username, filename)

	inodefinal, err := json.Marshal(inode)
	xrc := userlib.NewHMAC(inodefinal)
	_, err = xrc.Write(inodefinal)
	inodehmac := xrc.Sum(nil)

	inodefinal, err = encodemacanddata(inodefinal, inodehmac)

	userlib.CFBEncrypter(x, filerecord.IV).XORKeyStream(inodefinal, inodefinal)
	userlib.DatastoreSet(inodekey, inodefinal)

	return
}

// AppendFile should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	if len(data)%configBlockSize != 0 {
		return errors.New("something went wrong in appending")
	}

	var x = make([]byte, 16)

	//loading file record...
	var rec fileRecord
	rec, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, false, rec)

	key := string(rec.Inodelocation)

	if rec.Sharingflag {
		copy(x, rec.Sharedkey)
	} else {

		copy(x, userdata.Argon2key)
	}

	inode, flag := userlib.DatastoreGet(key)
	if flag == false {
		return errors.New("Something Wrong")
	}

	userlib.CFBDecrypter(x, rec.IV).XORKeyStream(inode, inode)

	inode, hmac, err := decodemacanddata(inode)

	loadstorefilerecord(x, userdata.IV, userdata.Username+filename, true, rec)

	var inodes [][]byte
	if compare(inode, hmac) == false || err != nil {
		return err
	}

	err = json.Unmarshal(inode, &inodes)

	nextindex := len(inodes)

	inodes, err = storeiterater(data, inodes, x, rec.IV, nextindex, userdata.Username, filename)

	inodefinal, err := json.Marshal(inodes)
	xrcc := userlib.NewHMAC(inodefinal)
	_, err = xrcc.Write(inodefinal)
	inodehmac := xrcc.Sum(nil)

	inodefinal, err = encodemacanddata(inodefinal, inodehmac)

	userlib.CFBEncrypter(x, rec.IV).XORKeyStream(inodefinal, inodefinal)

	userlib.DatastoreSet(key, inodefinal)
	return
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	var x = make([]byte, 16)
	if userdata == nil {
		return nil, errors.New("error")
	}
	//loading inode...
	var record fileRecord
	record, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, false, record)

	//fmt.Println(record.Fileowner)
	if record.Sharingflag == true {
		copy(x, record.Sharedkey)
	} else {
		copy(x, userdata.Argon2key)
	}

	inode, locstatusflag := userlib.DatastoreGet(string(record.Inodelocation))
	//fmt.Println(record.Inodelocation)

	if locstatusflag == false {
		return nil, err
	}

	userlib.CFBDecrypter(x, record.IV).XORKeyStream(inode, inode)

	inode, mac, err := decodemacanddata(inode)
	if compare(inode, mac) == false || err != nil {
		return nil, err
	}
	var inodes [][]byte
	err = json.Unmarshal(inode, &inodes)
	//fmt.Println(inodes[offset])
	//fmt.Println(inodes[offset])

	decfilerec, flag := userlib.DatastoreGet(string(inodes[offset]))
	if flag == false {
		return nil, errors.New("Something Wrong")
	}

	x[0] = x[0] ^ byte(offset)
	y := record.IV
	y[0] = y[0] ^ byte(offset)
	userlib.CFBDecrypter(x, y).XORKeyStream(decfilerec, decfilerec)

	decfilerec, hmac, err := decodemacanddata(decfilerec)
	//fmt.Println(decfilerec[4000:])
	//fmt.Println(hmac)
	//sxxx := userlib.NewHMAC(decfilerec)
	//sxxx.Write(decfilerec)
	//fmt.Println(sxxx.Sum(nil))
	var letmebetemp = make([]byte, configBlockSize)
	copy(letmebetemp, decfilerec)

	if compare(append(letmebetemp, inodes[offset]...), hmac) {
		//json.Unmarshal(decfilerec, &dd)
		data = decfilerec
		//fmt.Println(decfilerec[4000:])
		return
	}

	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	var rec fileRecord
	rec, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, false, rec)

	if rec.Sharingflag == false {
		pass := userlib.RandomBytes(8192)
		sharekey := userlib.Argon2Key(pass, []byte(filename), 16)
		rec.Sharingflag = true
		rec.Sharedkey = sharekey

		var x = make([]byte, 16)
		copy(x, userdata.Argon2key)

		//Loading inode...
		inode, flag := userlib.DatastoreGet(string(rec.Inodelocation))
		if flag == false {
			return "", errors.New("Something Wrong")
		}

		userlib.CFBDecrypter(x, rec.IV).XORKeyStream(inode, inode)

		inode1, inodehmac, err := decodemacanddata(inode)

		if compare(inode1, inodehmac) == false || err != nil {
			return "", err
		}
		var inodes [][]byte
		err = json.Unmarshal(inode1, &inodes)
		//Loading inode done...

		size := len(inodes)

		for i := 0; i < size; i++ {
			var tempkey = make([]byte, 16)
			copy(tempkey, x)
			var tempiv = make([]byte, 16)
			copy(tempiv, rec.IV)

			tempkey[0] = tempkey[0] ^ byte(i)
			tempiv[0] = tempiv[0] ^ byte(i)
			tempdata, flag := userlib.DatastoreGet(string(inodes[i])) //get block i
			if flag == false {
				return "", errors.New("Something Wrong")
			}

			userlib.CFBDecrypter(tempkey, tempiv).XORKeyStream(tempdata, tempdata) // decrypt block i

			tempdata1, datahmac, err := decodemacanddata(tempdata)
			var letmebetemp = make([]byte, configBlockSize)
			copy(letmebetemp, tempdata1)

			if compare(append(letmebetemp, inodes[i]...), datahmac) == false || err != nil {
				return "", err
			}

			var tempforshare = make([]byte, 16)
			copy(tempforshare, sharekey)

			tempforshare[0] = tempforshare[0] ^ byte(i)
			userlib.CFBEncrypter(tempforshare, tempiv).XORKeyStream(tempdata, tempdata)
			userlib.DatastoreSet(string(inodes[i]), tempdata)

		}

		userlib.CFBEncrypter(sharekey, rec.IV).XORKeyStream(inode, inode)
		userlib.DatastoreSet(string(rec.Inodelocation), inode)

		_, err = loadstorefilerecord(x, userdata.IV, userdata.Username+filename, true, rec)
	}

	message := []byte(rec.Fileowner + " % " + string(rec.Sharedkey) + " % " + string(rec.Inodelocation) + " % " + string(rec.IV))
	xscc := userlib.NewHMAC(message)
	_, err = xscc.Write(message)
	messagehmac := xscc.Sum(nil)

	encodemessage, err := encodemacanddata(message, messagehmac)

	y, _ := userlib.KeystoreGet(recipient)
	encmessage, err := userlib.RSAEncrypt(&y, []byte(encodemessage), []byte("share"))

	signature, err := userlib.RSASign(userdata.Privatekey, encmessage)

	finalmessage, err := encodemacanddata(encmessage, signature)

	msgid = string(finalmessage)
	return msgid, err
}

// ReceiveFile The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	message, signature, err := decodemacanddata([]byte(msgid))

	y, flag := userlib.KeystoreGet(sender)

	if flag == false {
		return errors.New("Something Wrong")
	}

	err = userlib.RSAVerify(&y, message, signature)
	if err != nil {
		return err
	}
	decmessage, err := userlib.RSADecrypt(userdata.Privatekey, message, []byte("share"))
	decmessage, hmac, err := decodemacanddata(decmessage)

	if compare(decmessage, hmac) == false {
		return errors.New("Someone has modified data illegaly")
	}
	messagestr := string(decmessage)

	marray := strings.Split(messagestr, " % ")

	var rec fileRecord
	rec.Fileowner = marray[0]
	rec.Sharedkey = []byte(marray[1])
	rec.Inodelocation = []byte(marray[2])
	rec.IV = []byte(marray[3])
	rec.Sharingflag = true

	_, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, true, rec)

	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	var rec fileRecord
	rec, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, false, rec)
	if rec.Sharingflag == false {
		return errors.New("Something went wrong in Revoking file please try again")
	}
	if rec.Fileowner != userdata.Username {
		return errors.New("Something went wrong in Revoking file please try again")
	}
	var x = make([]byte, 16)
	copy(x, rec.Sharedkey)

	rec.Sharedkey = []byte{0}
	rec.Sharingflag = false

	//Loading inode...
	inode, flagforinode := userlib.DatastoreGet(string(rec.Inodelocation))

	if flagforinode == false {
		return errors.New("Something Wrong")
	}
	userlib.CFBDecrypter(x, rec.IV).XORKeyStream(inode, inode)

	inode1, inodehmac, err := decodemacanddata(inode)

	if compare(inode1, inodehmac) == false {
		return err
	}
	var inodes [][]byte
	err = json.Unmarshal(inode1, &inodes)
	//Loading inode done...

	//re-encrypting file blocks...
	size := len(inodes)

	for i := 0; i < size; i++ {
		var tempkey = make([]byte, 16)
		copy(tempkey, x)
		var tempiv = make([]byte, 16)
		copy(tempiv, rec.IV)

		tempkey[0] = tempkey[0] ^ byte(i)
		tempiv[0] = tempiv[0] ^ byte(i)
		tempdata, _ := userlib.DatastoreGet(string(inodes[i]))                 //get block i
		userlib.CFBDecrypter(tempkey, tempiv).XORKeyStream(tempdata, tempdata) // decrypt block i

		tempdata1, datahmac, err := decodemacanddata(tempdata)
		var letmebetemp = make([]byte, configBlockSize)
		copy(letmebetemp, tempdata1)

		if compare(append(letmebetemp, inodes[i]...), datahmac) == false || err != nil {
			return errors.New("unable to load file")
		}

		var tempforshare = make([]byte, 16)
		copy(tempforshare, userdata.Argon2key)

		tempforshare[0] = tempforshare[0] ^ byte(i)
		userlib.CFBEncrypter(tempforshare, tempiv).XORKeyStream(tempdata, tempdata)
		userlib.DatastoreSet(string(inodes[i]), tempdata)
	}
	userlib.CFBEncrypter(userdata.Argon2key, rec.IV).XORKeyStream(inode, inode)
	userlib.DatastoreDelete(string(rec.Inodelocation))

	key := generatekey(userdata.Argon2key, userdata.Username+filename+"changing location after revoke")
	rec.Inodelocation = []byte(key)

	userlib.DatastoreSet(key, inode)
	_, err = loadstorefilerecord(userdata.Argon2key, userdata.IV, userdata.Username+filename, true, rec)

	return err
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(password) == 0 {
		return userdataptr, errors.New("Error")
	}

	x := userlib.Argon2Key([]byte(password+username), []byte(username), 16)

	udskey := generatekey(x, username+password)

	_, flag := userlib.DatastoreGet(udskey)
	if flag == true {
		return userdataptr, errors.New("User already exist")
	}

	var user User

	user.Username = username

	user.Argon2key = x

	user.Privatekey, err = userlib.GenerateRSAKey()

	user.Filecount = 0

	user.IV = userlib.Argon2Key([]byte(username+"6295141.34537865"), []byte(password), 16)

	userdataptr = &user

	userlib.KeystoreSet(username, userdataptr.Privatekey.PublicKey)

	y, err := json.Marshal(userdataptr)

	xdcc := userlib.NewHMAC(x)
	_, err = xdcc.Write(y)
	temp := xdcc.Sum(nil)

	final, err := encodemacanddata(y, temp)

	userlib.CFBEncrypter(x, user.IV).XORKeyStream(final, final)

	userlib.DatastoreSet(udskey, final)

	return userdataptr, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	if len(password) == 0 {
		return nil, errors.New("unable to load file")
	}

	x := userlib.Argon2Key([]byte(password+username), []byte(username), 16)

	udskey := generatekey(x, username+password)

	encobj, b := userlib.DatastoreGet(udskey)

	if b != true {
		return nil, errors.New("something")
	}

	userlib.CFBDecrypter(x, userlib.Argon2Key([]byte(username+"6295141.34537865"), []byte(password), 16)).XORKeyStream(encobj, encobj)

	data, mac, err := decodemacanddata(encobj)

	frcx := userlib.NewHMAC(x)
	_, err = frcx.Write(data)
	hmac := frcx.Sum(nil)

	if err != nil {
		return nil, err
	}

	var usr User
	if userlib.Equal(hmac, mac) {

		err = json.Unmarshal(data, &usr)
		userdataptr = &usr
		if userdataptr.Username != username || userlib.Equal(userdataptr.Argon2key, x) == false {

			err = errors.New("error")
			return nil, err
		}
		return userdataptr, err
	}
	return nil, err
}
