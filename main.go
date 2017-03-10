package main

//TODO: Create cookie for the files
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var err error
var tpl *template.Template
var xs []string
var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func signupPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "templates/signup.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")
	//grab file name

	var user string

	err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		res.Write([]byte("User created!"))
		return
	case err != nil:
		http.Error(res, "Server error, unable to create your account.", 500)
		return
	default:
		http.Redirect(res, req, "/", 301)
	}
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "templates/login.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	err := db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&databaseUsername, &databasePassword)

	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	res.Write([]byte("Hello " + databasePassword))

}

func getCookie(res http.ResponseWriter, req *http.Request) *http.Cookie {
	c, err := req.Cookie("session")
	if err != nil {
		sID := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(res, c)
	}
	return c
}

func appendValue(res http.ResponseWriter, c *http.Cookie, fname string) *http.Cookie {
	s := c.Value
	if !strings.Contains(s, fname) {
		s += "|" + fname
	}
	c.Value = s
	http.SetCookie(res, c)
	return c
}

func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "templates/index.html")
}
func cookiePage(res http.ResponseWriter, req *http.Request) {
	c := getCookie(res, req)
	if req.Method == http.MethodPost {
		// mf == multipart file fh== *multipart header
		mf, fh, err := req.FormFile("fileName")
		if err != nil {
			fmt.Println(err)
		}
		defer mf.Close()

		ext := strings.Split(fh.Filename, ".")[1]
		h := sha1.New()
		io.Copy(h, mf)

		fname := fmt.Sprintf("%x", h.Sum(nil))[:10] + "." + ext

		wd, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}
		path := filepath.Join(wd, "public", "pics", fname)
		nf, err := os.Create(path)
		if err != nil {
			fmt.Println(err)
		}
		defer nf.Close()

		mf.Seek(0, 0)
		io.Copy(nf, mf)
		c = appendValue(res, c, fname)
		xs = strings.Split(c.Value, "|")
		xs, _ = remove(xs, 0)
		picString := strings.Join(xs, "|")
		encryptData(res, req, []byte(picString))
	}
	tpl.ExecuteTemplate(res, "cookie.gohtml", xs)
	/*The ciperr starts here*/
	// Need to encrypt a string
}

func encryptData(res http.ResponseWriter, req *http.Request, src []byte) []byte {

	plaintext := []byte(src)

	// If there is an incoming string of words to be encrypted, set plaintext to that incoming string
	if len(os.Args) > 1 {
		plaintext = []byte(os.Args[1])
	}

	// aes encryption string
	keyText := "astaxie12798akljzmknm.ahkjkljl;k"
	if len(os.Args) > 2 {
		keyText = os.Args[2]
	}

	fmt.Println(len(keyText))

	// Create the aes encryption algorithm
	ci, err := aes.NewCipher([]byte(keyText))
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes) = %s", len(keyText), err)
		os.Exit(-1)
	}

	// Encrypted string
	var id int

	err = db.QueryRow("SELECT EXISTS(SELECT pics FROM pichash WHERE id = 1)").Scan(&id)

	if err != nil {
		return nil
	}
	fmt.Println(err)
	cfb := cipher.NewCFBEncrypter(ci, commonIV)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)
	fmt.Printf("%s=>\n%x\n", plaintext, ciphertext)
	cipherString := fmt.Sprintf("%x\n", ciphertext)

	_, err = db.Exec("INSERT INTO pichash(pics) VALUES(?)", cipherString)
	fmt.Println(err)
	// Decrypt strings

	return src
}

func decrypt(ci cipher.Block, src []byte, ciphertext []byte) []byte {
	cfbdec := cipher.NewCFBDecrypter(ci, commonIV)
	plaintextCopy := make([]byte, len(src))
	cfbdec.XORKeyStream(plaintextCopy, ciphertext)
	fmt.Printf("%x=>\n%s\n", ciphertext, plaintextCopy)

	return plaintextCopy
}
func remove(s []string, index int) ([]string, error) {
	if index >= len(s) {
		return nil, errors.New("Out of Range Error")
	}
	return append(s[:index], s[index+1:]...), nil
}

func main() {

	db, err = sql.Open("mysql", "root:1234@/user")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/cookie", cookiePage)
	http.HandleFunc("/", homePage)
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("./public"))))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":1234", nil)
}
