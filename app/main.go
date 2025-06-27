// main.go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	http.HandleFunc("/user", getUserHandler)
	log.Println("Starting server on :8085")
	http.ListenAndServe(":8085", nil)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserByID(1, "this should be traced")
	fmt.Fprintf(w, "User: %s \n", user)
}

func getUserByID(id int, traceable string) string {
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
