// main.go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	http.HandleFunc("/user/", getUserHandler)
	sample()
	time.Sleep(1 * time.Second)
	sample()
	time.Sleep(1 * time.Second)
	sample()
	time.Sleep(1 * time.Second)
	sample()
	time.Sleep(1 * time.Second)
	sample()
	log.Println("Starting server on :8085")
	http.ListenAndServe(":8084", nil)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	fmt.Printf("Query params: %s\n", query)
	if query.Has("2"){
		println("yes 2")
	}
	
	user := getUserByID(1, "biggestString")
	fmt.Fprintf(w, "User: %s \n", user)
}

func getUserByID(id int, str string) string {
	println(str)
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var name string
	err = db.QueryRow("SELECT name FROM users WHERE id = ?", id).Scan(&name)
	if err != nil {
		log.Fatal(err)
	}
	return name
}

func sample() string {
	println("sample")
	return "yo"
}